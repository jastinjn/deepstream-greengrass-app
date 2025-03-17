import sys
import gi
gi.require_version('Gst', '1.0')
from gi.repository import GLib, Gst, GstRtspServer
from common.bus_call import bus_call
from common.FPS import PERF_DATA
from common.utils import long_to_uint64
import pyds
import argparse

silent = False
perf_data = None

MAX_TIME_STAMP_LEN = 32

# Callback function for deep-copying an NvDsEventMsgMeta struct
def meta_copy_func(data, user_data):
    # Cast data to pyds.NvDsUserMeta
    user_meta = pyds.NvDsUserMeta.cast(data)
    src_meta_data = user_meta.user_meta_data
    # Cast src_meta_data to pyds.NvDsEventMsgMeta
    srcmeta = pyds.NvDsEventMsgMeta.cast(src_meta_data)
    # Duplicate the memory contents of srcmeta to dstmeta
    # First use pyds.get_ptr() to get the C address of srcmeta, then
    # use pyds.memdup() to allocate dstmeta and copy srcmeta into it.
    # pyds.memdup returns C address of the allocated duplicate.
    dstmeta_ptr = pyds.memdup(pyds.get_ptr(srcmeta),
                              sys.getsizeof(pyds.NvDsEventMsgMeta))
    # Cast the duplicated memory to pyds.NvDsEventMsgMeta
    dstmeta = pyds.NvDsEventMsgMeta.cast(dstmeta_ptr)

    # Duplicate contents of ts field. Note that reading srcmeat.ts
    # returns its C address. This allows to memory operations to be
    # performed on it.
    dstmeta.ts = pyds.memdup(srcmeta.ts, MAX_TIME_STAMP_LEN + 1)

    # Copy the sensorStr. This field is a string property. The getter (read)
    # returns its C address. The setter (write) takes string as input,
    # allocates a string buffer and copies the input string into it.
    # pyds.get_string() takes C address of a string and returns the reference
    # to a string object and the assignment inside the binder copies content.
    dstmeta.sensorStr = pyds.get_string(srcmeta.sensorStr)

    return dstmeta


# Callback function for freeing an NvDsEventMsgMeta instance
def meta_free_func(data, user_data):
    user_meta = pyds.NvDsUserMeta.cast(data)
    srcmeta = pyds.NvDsEventMsgMeta.cast(user_meta.user_meta_data)

    # pyds.free_buffer takes C address of a buffer and frees the memory
    # It's a NOP if the address is NULL
    pyds.free_buffer(srcmeta.ts)
    pyds.free_buffer(srcmeta.sensorStr)
    

def generate_event_msg_meta(data):
    meta = pyds.NvDsEventMsgMeta.cast(data)
    meta.sensorId = 0
    meta.placeId = 0
    meta.moduleId = 0
    meta.sensorStr = "sensor-0"
    meta.ts = pyds.alloc_buffer(MAX_TIME_STAMP_LEN + 1)
    pyds.generate_ts_rfc3339(meta.ts, MAX_TIME_STAMP_LEN)

    return meta

# nvanlytics_src_pad_buffer_probe  will extract metadata received on nvtiler sink pad
# and update params for drawing rectangle, object information etc.
def nvanalytics_src_pad_buffer_probe(pad,info,u_data):
    gst_buffer = info.get_buffer()
    if not gst_buffer:
        print("Unable to get GstBuffer ")
        return

    # Retrieve batch metadata from the gst_buffer
    # Note that pyds.gst_buffer_get_nvds_batch_meta() expects the
    # C address of gst_buffer as input, which is obtained with hash(gst_buffer)
    batch_meta = pyds.gst_buffer_get_nvds_batch_meta(hash(gst_buffer))
    l_frame = batch_meta.frame_meta_list

    while l_frame:
        try:
            # Note that l_frame.data needs a cast to pyds.NvDsFrameMeta
            # The casting is done by pyds.NvDsFrameMeta.cast()
            # The casting also keeps ownership of the underlying memory
            # in the C code, so the Python garbage collector will leave
            # it alone.
            frame_meta = pyds.NvDsFrameMeta.cast(l_frame.data)
        except StopIteration:
            break
        
        frame_number = frame_meta.frame_num
        l_obj=frame_meta.obj_meta_list
        while l_obj:
            try: 
                # Note that l_obj.data needs a cast to pyds.NvDsObjectMeta
                # The casting is done by pyds.NvDsObjectMeta.cast()
                obj_meta=pyds.NvDsObjectMeta.cast(l_obj.data)
            except StopIteration:
                break
            
            in_roi = False
            l_user_meta = obj_meta.obj_user_meta_list
            # Extract object level meta data from NvDsAnalyticsObjInfo
            while l_user_meta:
                try:
                    user_meta = pyds.NvDsUserMeta.cast(l_user_meta.data)
                    if user_meta.base_meta.meta_type == pyds.nvds_get_user_meta_type("NVIDIA.DSANALYTICSOBJ.USER_META"):             
                        user_meta_data = pyds.NvDsAnalyticsObjInfo.cast(user_meta.user_meta_data)
                        if 'TL1' in user_meta_data.roiStatus:
                            in_roi = True
                            
                            if (frame_number % 30) == 0:
                                msg_meta = pyds.alloc_nvds_event_msg_meta()
                                msg_meta.bbox.top = obj_meta.rect_params.top
                                msg_meta.bbox.left = obj_meta.rect_params.left
                                msg_meta.bbox.width = obj_meta.rect_params.width
                                msg_meta.bbox.height = obj_meta.rect_params.height
                                msg_meta.frameId = frame_number
                                msg_meta.trackingId = long_to_uint64(obj_meta.object_id)
                                msg_meta.confidence = obj_meta.confidence
                                msg_meta.objClassId = obj_meta.class_id
                                msg_meta.sensorId = 0
                                msg_meta.placeId = 0
                                msg_meta.moduleId = 0
                                msg_meta.sensorStr = "sensor-0"
                                msg_meta.ts = pyds.alloc_buffer(MAX_TIME_STAMP_LEN + 1)
                                pyds.generate_ts_rfc3339(msg_meta.ts, MAX_TIME_STAMP_LEN)
                                user_event_meta = pyds.nvds_acquire_user_meta_from_pool(
                                    batch_meta)
                                if user_event_meta:
                                    user_event_meta.user_meta_data = msg_meta
                                    user_event_meta.base_meta.meta_type = pyds.NvDsMetaType.NVDS_EVENT_MSG_META
                                    # Setting callbacks in the event msg meta. The bindings
                                    # layer will wrap these callables in C functions.
                                    # Currently only one set of callbacks is supported.
                                    pyds.user_copyfunc(user_event_meta, meta_copy_func)
                                    pyds.user_releasefunc(user_event_meta, meta_free_func)
                                    pyds.nvds_add_user_meta_to_frame(frame_meta,
                                                                    user_event_meta)
                                else:
                                    print("Error in attaching event meta to buffer\n")
                        
                        # if user_meta_data.roiStatus: print("Object {0} roi status: {1}".format(obj_meta.object_id, user_meta_data.roiStatus))
                except StopIteration:
                    break

                try:
                    l_user_meta = l_user_meta.next
                except StopIteration:
                    break
            try: 
                l_obj=l_obj.next

                # if not in roi, remove bbox from drawing
                if not in_roi:
                    pyds.nvds_remove_obj_meta_from_frame(frame_meta, obj_meta)
            except StopIteration:
                break
        
        
        # Update frame rate through this probe
        stream_index = "stream{0}".format(frame_meta.pad_index)
        global perf_data
        perf_data.update_fps(stream_index)
        try:
            l_frame=l_frame.next
        except StopIteration:
            break
        #print("#"*50)

    return Gst.PadProbeReturn.OK

def cb_newpad(decodebin, decoder_src_pad,data):
    print("In cb_newpad\n")
    caps=decoder_src_pad.get_current_caps()
    if not caps:
        caps = decoder_src_pad.query_caps()
    gststruct=caps.get_structure(0)
    gstname=gststruct.get_name()
    source_bin=data
    features=caps.get_features(0)

    # Need to check if the pad created by the decodebin is for video and not
    # audio.
    print("gstname=",gstname)
    if(gstname.find("video")!=-1):
        # Link the decodebin pad only if decodebin has picked nvidia
        # decoder plugin nvdec_*. We do this by checking if the pad caps contain
        # NVMM memory features.
        print("features=",features)
        if features.contains("memory:NVMM"):
            # Get the source bin ghost pad
            bin_ghost_pad=source_bin.get_static_pad("src")
            if not bin_ghost_pad.set_target(decoder_src_pad):
                sys.stderr.write("Failed to link decoder src pad to source bin ghost pad\n")
        else:
            sys.stderr.write(" Error: Decodebin did not pick nvidia decoder plugin.\n")

def decodebin_child_added(child_proxy,Object,name,user_data):
    print("Decodebin child added:", name, "\n")
    if(name.find("decodebin") != -1):
        Object.connect("child-added",decodebin_child_added,user_data)

    if "source" in name:
        source_element = child_proxy.get_by_name("source")
        if source_element.find_property('drop-on-latency') != None:
            Object.set_property("drop-on-latency", True)

def create_source_bin(index,uri):
    print("Creating source bin")

    # Create a source GstBin to abstract this bin's content from the rest of the
    # pipeline
    bin_name="source-bin-%02d" %index
    print(bin_name)
    nbin=Gst.Bin.new(bin_name)
    if not nbin:
        sys.stderr.write(" Unable to create source bin \n")

    # Source element for reading from the uri.
    # We will use decodebin and let it figure out the container format of the
    # stream and the codec and plug the appropriate demux and decode plugins.
    
    uri_decode_bin=Gst.ElementFactory.make("uridecodebin", "uri-decode-bin")
    if not uri_decode_bin:
        sys.stderr.write(" Unable to create uri decode bin \n")
    # We set the input uri to the source element
    uri_decode_bin.set_property("uri",uri)
    # Connect to the "pad-added" signal of the decodebin which generates a
    # callback once a new pad for raw data has beed created by the decodebin
    uri_decode_bin.connect("pad-added",cb_newpad,nbin)
    uri_decode_bin.connect("child-added",decodebin_child_added,nbin)

    # We need to create a ghost pad for the source bin which will act as a proxy
    # for the video decoder src pad. The ghost pad will not have a target right
    # now. Once the decode bin creates the video decoder and generates the
    # cb_newpad callback, we will set the ghost pad target to the video decoder
    # src pad.
    Gst.Bin.add(nbin,uri_decode_bin)
    bin_pad=nbin.add_pad(Gst.GhostPad.new_no_target("src",Gst.PadDirection.SRC))
    if not bin_pad:
        sys.stderr.write(" Failed to add ghost pad in source bin \n")
        return None
    return nbin

# DeepStream configuration for the application

def main(stream_path, requested_pgie=None, pgie_config=None, conn_str=None, display=None):
    
    # initialise performance tracking
    global perf_data
    perf_data = PERF_DATA(1)
    
    # Initialize GST
    Gst.init(None)
   
    # Create the pipeline
    pipeline = Gst.Pipeline()

    # Streammux
    streammux = Gst.ElementFactory.make('nvstreammux', 'streammux')
    if not streammux:
        print("Streammux element could not be created!")
        sys.exit(1)
    pipeline.add(streammux)

    # Set streammux properties
    streammux.set_property('live-source', 0)
    streammux.set_property('batch-size', 1)
    streammux.set_property('width', 1280)
    streammux.set_property('height', 720)
    
    # Create the video source
    source_bin=create_source_bin(0, stream_path)
    if not source_bin:
        sys.stderr.write("Unable to create source bin \n")
    pipeline.add(source_bin)
    
    sinkpad= streammux.get_request_pad("sink_0")
    if not sinkpad:
        sys.stderr.write("Unable to create sink pad bin \n")
    	
    srcpad=source_bin.get_static_pad("src")
    if not srcpad:
        sys.stderr.write("Unable to create src pad bin \n")
    
    srcpad.link(sinkpad) 

    # Create the primary inference element (GIE)
    if requested_pgie != None and (requested_pgie == 'nvinferserver') :
        primary_gie = Gst.ElementFactory.make("nvinferserver", "primary-gie")
    else:
        primary_gie = Gst.ElementFactory.make("nvinfer", "primary-gie")
    if not primary_gie:
        print("Primary GIE element could not be created!")
        sys.exit(1)

    if pgie_config == None:
        primary_gie.set_property('config-file-path', 'config_infer_primary_rtdetr.txt')
    else:
        primary_gie.set_property('config-file-path', pgie_config)
    
    # Create the tracker
    tracker = Gst.ElementFactory.make('nvtracker', 'tracker')
    if not tracker:
        print("Tracker element could not be created!")
        sys.exit(1)

    tracker.set_property('ll-lib-file', '/opt/nvidia/deepstream/deepstream/lib/libnvds_nvmultiobjecttracker.so')
    tracker.set_property('ll-config-file', 'config_tracker_NvSORT.yml')
    tracker.set_property('gpu-id', 0)
    tracker.set_property('display-tracking-id', 1)
    
    # Create analytics
    nvanalytics = Gst.ElementFactory.make("nvdsanalytics", "analytics")
    if not nvanalytics:
        sys.stderr.write(" Unable to create nvanalytics \n")
    nvanalytics.set_property("config-file", "config_nvdsanalytics.txt")
    
    # Create tiler
    tiler=Gst.ElementFactory.make("nvmultistreamtiler", "nvtiler")
    if not tiler:
        sys.stderr.write(" Unable to create tiler \n")
    
    tiler.set_property("rows", 1)
    tiler.set_property("columns",1)
    tiler.set_property("width", 1280)
    tiler.set_property("height", 720)
    
    # Create nvvidconv (video converter)
    nvvidconv = Gst.ElementFactory.make('nvvideoconvert', 'nvvidconv')
    if not nvvidconv:
        print("Nvvidconv element could not be created!")
        sys.exit(1)

    # Create the OSD (On-Screen Display)
    osd = Gst.ElementFactory.make('nvdsosd', 'osd')
    if not osd:
        print("OSD element could not be created!")
        sys.exit(1)

    osd.set_property('gpu-id', 0)
    osd.set_property('display-clock', 0)
    osd.set_property('x-clock-offset', 800)
    osd.set_property('y-clock-offset', 820)
    osd.set_property('clock-font-size', 12)
    osd.set_property('clock-color', 0xff0000ff)
    
    # create the message converter
    msgconv = Gst.ElementFactory.make("nvmsgconv", "nvmsg-converter")
    if not msgconv:
        sys.stderr.write(" Unable to create msgconv \n")

    msgconv.set_property('config', 'msgconv_config.txt')
    msgconv.set_property('payload-type', 1)

    # create the message broker
    msgbroker = Gst.ElementFactory.make("nvmsgbroker", "nvmsg-broker")
    if not msgbroker:
        sys.stderr.write(" Unable to create msgbroker \n")

    msgbroker.set_property('proto-lib', '/opt/nvidia/deepstream/deepstream/lib/libnvds_kafka_proto.so')
    msgbroker.set_property('conn-str', conn_str)

    # Create the sink (display output)
    if display != None and display == "no-display":
        sink = Gst.ElementFactory.make("fakesink", "fakesink")
        if not sink:
            print("Unable to create fake sink")
            sys.exit(1)
        sink.set_property('enable-last-sample', 0)
    elif display != None and display == "rtsp":

        nvvidconv_postosd = Gst.ElementFactory.make("nvvideoconvert", "convertor_postosd")
        if not nvvidconv_postosd:
            sys.stderr.write(" Unable to create nvvidconv_postosd \n")
        # Create a caps filter
        caps = Gst.ElementFactory.make("capsfilter", "filter")
        caps.set_property("caps", Gst.Caps.from_string("video/x-raw(memory:NVMM), format=I420"))
        
        # Make the encoder
        
        encoder = Gst.ElementFactory.make("nvv4l2h264enc", "encoder")
        if not encoder:
            sys.stderr.write(" Unable to create encoder")
        encoder.set_property('bitrate', 4000000)
        encoder.set_property('preset-level', 1)
        encoder.set_property('insert-sps-pps', 1)
            
        # Make the payload-encode video into RTP packets
        rtppay = Gst.ElementFactory.make("rtph264pay", "rtppay")
        if not rtppay:
            sys.stderr.write(" Unable to create rtppay")
        
        # Make the UDP sink
        updsink_port_num = 5400
        sink = Gst.ElementFactory.make("udpsink", "udpsink")
        if not sink:
            sys.stderr.write(" Unable to create udpsink")
        
        sink.set_property('host', '224.224.255.255')
        sink.set_property('port', updsink_port_num)
        sink.set_property('async', False)
    else:
        sink = Gst.ElementFactory.make("nv3dsink", "nv3d-sink")
        if not sink:
            print("Unable to create nv3dsink")
            sys.exit(1)
       
    # if live video source or max 30 fps framerate, set to true
    sink.set_property('sync', 0)
        
    # Add elements to pipeline
    pipeline.add(primary_gie)
    pipeline.add(tracker)
    pipeline.add(nvanalytics)
    pipeline.add(tiler)
    pipeline.add(nvvidconv)
    pipeline.add(osd)
    pipeline.add(msgconv)
    pipeline.add(msgbroker)
    if display != None and display == "rtsp":
        pipeline.add(nvvidconv_postosd)
        pipeline.add(caps)
        pipeline.add(encoder)
        pipeline.add(rtppay)
    pipeline.add(sink)
    
    # Create queue elements for asynchronous pipeline
    queue1=Gst.ElementFactory.make("queue","queue1")
    queue2=Gst.ElementFactory.make("queue","queue2")
    queue3=Gst.ElementFactory.make("queue","queue3")
    tee = Gst.ElementFactory.make("tee", "nvsink-tee")
    queueT1 = Gst.ElementFactory.make("queue", "nvtee-que1")
    queueT2 = Gst.ElementFactory.make("queue", "nvtee-que2")
    pipeline.add(queue1)
    pipeline.add(queue2)
    pipeline.add(queue3)
    pipeline.add(tee)
    pipeline.add(queueT1)
    pipeline.add(queueT2)

    # Link elements
    streammux.link(queue1)
    queue1.link(primary_gie)
    primary_gie.link(queue2)
    queue2.link(tracker)
    tracker.link(queue3)
    queue3.link(nvanalytics)
    nvanalytics.link(tiler)
    tiler.link(nvvidconv)
    nvvidconv.link(osd)
    osd.link(tee)
    
    sink_pad1 = queueT1.get_static_pad("sink")
    sink_pad2 = queueT2.get_static_pad("sink")
    tee_msg_pad = tee.get_request_pad('src_%u')
    tee_render_pad = tee.get_request_pad("src_%u")
    if not tee_msg_pad or not tee_render_pad:
        sys.stderr.write("Unable to get request pads\n")
    tee_msg_pad.link(sink_pad1)
    tee_render_pad.link(sink_pad2)
    queueT1.link(msgconv)
    msgconv.link(msgbroker)
    if display != None and display == "rtsp":
        queueT2.link(nvvidconv_postosd)
        nvvidconv_postosd.link(caps)
        caps.link(encoder)
        encoder.link(rtppay)
        rtppay.link(sink)
    else:
        queueT2.link(sink)
    
    # Initialize loop
    loop = GLib.MainLoop()
    bus = pipeline.get_bus()
    bus.add_signal_watch()
    bus.connect ("message", bus_call, loop)

    if display != None and display == "rtsp":
        # Start streaming
        rtsp_port_num = 8554
        
        server = GstRtspServer.RTSPServer.new()
        server.props.service = "%d" % rtsp_port_num
        server.attach(None)
        
        factory = GstRtspServer.RTSPMediaFactory.new()
        factory.set_launch( "( udpsrc name=pay0 port=%d buffer-size=524288 caps=\"application/x-rtp, media=video, clock-rate=90000, encoding-name=(string)%s, payload=96 \" )" % (updsink_port_num, "H264"))
        factory.set_shared(True)
        server.get_mount_points().add_factory("/0", factory)
        
        print("\n *** DeepStream: Launched RTSP Streaming at rtsp://localhost:%d/0 ***\n\n" % rtsp_port_num)
    
    # Add probes
    nvanalytics_src_pad=nvanalytics.get_static_pad("src")
    if not nvanalytics_src_pad:
        sys.stderr.write(" Unable to get src pad \n")
    else:
        nvanalytics_src_pad.add_probe(Gst.PadProbeType.BUFFER, nvanalytics_src_pad_buffer_probe, 0)
        # perf callback function to print fps every 5 sec
        if not silent:
            GLib.timeout_add(1000, perf_data.perf_print_callback)
        
    # Start playing the pipeline
    pipeline.set_state(Gst.State.PLAYING)

    # Start the main loop
    try:  
        loop.run()
    except Exception as e:
        print("Error during pipeline execution:", e)
        pass
   
    pipeline.set_state(Gst.State.NULL)
   
def parse_args():

    parser = argparse.ArgumentParser(prog="traffic-detector-nvds",
                    description="traffic monitoring")
    parser.add_argument(
        "-i",
        "--input",
        help="Path to input stream",
        metavar="URI",
        default=None,
        required=True,
    )
    parser.add_argument(
        "-c",
        "--configfile",
        metavar="config_location.txt",
        default=None,
        help="Choose the config-file to be used with specified pgie",
    )
    parser.add_argument(
        "-g",
        "--pgie",
        default=None,
        help="Choose Primary GPU Inference Engine",
        choices=["nvinfer", "nvinferserver"],
    )
    parser.add_argument(
        "--conn-str", 
        dest="conn_str",
        default="localhost;9092;quickstart-events",
        help="Connection string of backend server in the format host;port;topic", 
        metavar="STR")
    parser.add_argument(
        "-d",
        "--display",
        default=None,
        help="Display type for video output",
        choices=["osd", "no-display", "rtsp"],
    )
    parser.add_argument(
        "-s",
        "--silent",
        action="store_true",
        default=False,
        dest='silent',
        help="Disable verbose output",
    )
   
    # Check input arguments
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()

    stream_path = args.input
    pgie = args.pgie
    config = args.configfile
    conn_str = args.conn_str

    global silent
    display = args.display
    silent = args.silent
   
    if config and not pgie or pgie and not config:
        sys.stderr.write ("\nEither pgie or configfile is missing. Please specify both! Exiting...\n\n\n\n")
        parser.print_help()
        sys.exit(1)
    
    print(vars(args))
    return stream_path, pgie, config, conn_str, display


if __name__ == "__main__":
    stream_path, pgie, config, conn_str, display = parse_args()
    sys.exit(main(stream_path, pgie, config, conn_str, display))
