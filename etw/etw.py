########################################################################
# Copyright 2017 FireEye Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
########################################################################

# Public packages
import threading
import logging
import uuid
import time
import traceback
import ctypes as ct
import ctypes.wintypes as wt

# Custom packages
from etw import evntrace as et
from etw import evntprov as ep
from etw import in6addr as ia
from etw import evntcons as ec
from etw import wmistr as ws
from etw import tdh as tdh
from etw.common import rel_ptr_to_str, MAX_UINT, ETWException, RETURN_RAW_DATA_ONLY, RETURN_RAW_DATA_ON_ERROR, \
    RETURN_ONLY_RAW_DATA_ON_ERROR, RETURN_RAW_UNFORMATTED_DATA

logger = logging.getLogger(__name__)


class TraceProperties:
    """
    The TraceProperties class represents the EVENT_TRACE_PROPERTIES structure. The class wraps
    this structure to make it easier to interact with.
    """

    def __init__(self, ring_buf_size=1024, max_str_len=1024, min_buffers=0, max_buffers=0, props=None):
        """
        Initializes an EVENT_TRACE_PROPERTIES structure.

        :param ring_buf_size: The size of the ring buffer used for capturing events.
        :param max_str_len: The maximum length of the strings the proceed the structure.
                            Unless you know what you are doing, do not modify this value.
        :param min_buffers: The minimum number of buffers for an event tracing session.
                            Unless you know what you are doing, do not modify this value.
        :param max_buffers: The maximum number of buffers for an event tracing session.
                            Unless you know what you are doing, do not modify this value.
        :param props: pointer to a EVENT_TRACE_PROPERTIES structure to use for the capture session.
                      Use this when you wish to set all trace properties. If this is used then ring_buf_size,
                      min_buffers, and max_buffers are ignored.
        """
        # In this structure, the LoggerNameOffset and other string fields reside immediately
        # after the EVENT_TRACE_PROPERTIES structure. So allocate enough space for the
        # structure and any strings we are using.
        buf_size = ct.sizeof(et.EVENT_TRACE_PROPERTIES) + 2 * ct.sizeof(ct.c_wchar) * max_str_len

        # noinspection PyCallingNonCallable
        self._buf = (ct.c_char * buf_size)()
        self._props = ct.cast(ct.pointer(self._buf), ct.POINTER(et.EVENT_TRACE_PROPERTIES))

        if props:
            ct.memmove(self._props, props, ct.sizeof(et.EVENT_TRACE_PROPERTIES))
        else:
            self._props.contents.BufferSize = ring_buf_size

            if min_buffers != 0:
                self._props.contents.MinimumBuffers = min_buffers

            if max_buffers != 0:
                self._props.contents.MaximumBuffers = max_buffers

            self._props.contents.Wnode.Flags = ws.WNODE_FLAG_TRACED_GUID
            self._props.contents.LogFileMode = et.EVENT_TRACE_REAL_TIME_MODE

        self._props.contents.Wnode.BufferSize = buf_size
        self._props.contents.LoggerNameOffset = ct.sizeof(et.EVENT_TRACE_PROPERTIES)

    def __eq__(self, other):
        for field in self.get().contents._fields_:
            attr_name = field[0]
            a, b = getattr(self.get().contents, attr_name), getattr(other.get().contents, attr_name)
            is_wnode = isinstance(a, ws.WNODE_HEADER)
            if is_wnode is True:
                for wnode_field in a._fields_:
                    wnode_attr_name = wnode_field[0]
                    a_wnode, b_wnode = getattr(a, wnode_attr_name), getattr(b, wnode_attr_name)
                    if a_wnode != b_wnode:
                        return False
            else:
                if a != b:
                    return False
        return True

    def get(self):
        """
        This class wraps the construction of a struct for ctypes. As a result, in order to properly use it as a ctypes
        structure, you must use the private field _props. To maintain proper encapsulation, this getter is used to
        retrieve this value when needed.

        :return: The _props field needed for using this class as a ctypes EVENT_TRACE_PROPERTIES structure.
        """
        return self._props


class EventProvider:
    """
    Wraps all interactions with Event Tracing for Windows (ETW) event providers. This includes
    starting and stopping them.

    N.B. If using this class, do not call start() and stop() directly. Only use through via ctxmgr
    """

    def __init__(
            self,
            session_name,
            session_properties,
            providers):
        """
        Sets the appropriate values for an ETW provider.

        :param session_name: The name of the provider session.
        :param session_properties: A TraceProperties instance used to specify the parameters for the provider
        :param providers: A list of ProviderInfo instances to use in the capture. Do not reuse providers.
        """

        # check if the session name is "NT Kernel Logger"
        self.kernel_trace = False
        self.kernel_trace_was_running = False
        if session_name.lower() == et.KERNEL_LOGGER_NAME_LOWER:
            self.session_name = et.KERNEL_LOGGER_NAME
            self.kernel_trace = True
        else:
            self.session_name = session_name

        self.providers = providers
        self.session_properties = session_properties
        self.session_handle = et.TRACEHANDLE()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc, ex, tb):
        self.stop()

    def start(self):
        """
        Wraps the necessary processes needed for starting an ETW provider session.

        :return:  Does not return anything.
        """
        self.kernel_trace_was_running = False
        if self.kernel_trace is True:
            provider = self.providers[0]  # there should only be one provider
            self.session_properties.get().contents.Wnode.Guid = provider.guid
            self.session_properties.get().contents.LogFileMode |= et.EVENT_TRACE_SYSTEM_LOGGER_MODE

            if provider.any_bitmask:
                self.session_properties.get().contents.EnableFlags = provider.any_bitmask
            else:
                self.session_properties.get().contents.EnableFlags = et.DEFAULT_NT_KERNEL_LOGGER_FLAGS

        status = et.StartTraceW(ct.byref(self.session_handle), self.session_name, self.session_properties.get())
        if status != tdh.ERROR_SUCCESS:
            if self.kernel_trace is True and status == tdh.ERROR_ALREADY_EXISTS:
                self.kernel_trace_was_running = True
            raise ct.WinError(status)

        if self.kernel_trace is False:
            for provider in self.providers:

                if provider.params:
                    provider.params.contents.SourceId = self.session_properties.get().contents.Wnode.Guid

                status = et.EnableTraceEx2(self.session_handle,
                                           ct.byref(provider.guid),
                                           et.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                           provider.level,
                                           provider.any_bitmask,
                                           provider.all_bitmask,
                                           0,
                                           provider.params)
                if status != tdh.ERROR_SUCCESS:
                    raise ct.WinError(status)

    def stop(self):
        """
        Wraps the necessary processes needed for stopping an ETW provider session.

        :return: Does not return anything
        """
        # don't stop if we don't have a handle, or it's the kernel trace and we started it ourself
        if (
            (self.session_handle.value == 0 and self.kernel_trace is False)
            or (self.kernel_trace is True and self.kernel_trace_was_running is True)
        ):
            return

        if self.kernel_trace is False:
            for provider in self.providers:

                status = et.EnableTraceEx2(self.session_handle,
                                           ct.byref(provider.guid),
                                           et.EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                                           provider.level,
                                           provider.any_bitmask,
                                           provider.all_bitmask,
                                           0,
                                           None)
                if status != tdh.ERROR_SUCCESS:
                    raise ct.WinError(status)

        status = et.ControlTraceW(self.session_handle,
                                  self.session_name,
                                  self.session_properties.get(),
                                  et.EVENT_TRACE_CONTROL_STOP)
        if status != tdh.ERROR_SUCCESS:
            raise ct.WinError(status)

        et.CloseTrace(self.session_handle)


class EventConsumer:
    """
    Wraps all interactions with Event Tracing for Windows (ETW) event consumers. This includes
    starting and stopping the consumer. Additionally, each consumer begins processing events in
    a separate thread and uses a callback to process any events it receives in this thread -- those
    methods are implemented here as well.

    N.B. If using this class, do not call start() and stop() directly. Only use through via ctxmgr
    """

    def __init__(self,
                 logger_name,
                 event_callback=None,
                 task_name_filters=None,
                 event_id_filters=None,
                 providers_event_id_filters=None,
                 pid_whitelist=None,
                 pid_blacklist=None,
                 callback_data_flag=0,
                 callback_wait_time=0.0,
                 trace_logfile=None):
        """
        Initializes a real time event consumer object.

        :param logger_name: The name of the session that we want to consume events from.
        :param event_callback: The optional callback function which can be used to return the values.
        :param task_name_filters: List of filters to apply to the ETW capture
        :param event_id_filters: List of event ids to filter on.
        :param providers_event_id_filters: Dict of provider/ list of ids to filter on.
        :param pid_whitelist: List of PID for which we want to receive events (only events for those PIDs will be processed).
        :param pid_blacklist: List of PID for which we don't want to receive events (events for all PIDs except those will be processed).
        :param callback_data_flag: Determines how to format data passed into callback.
        :param callback_wait_time: Time callback will sleep when called. If used, this may cause events to be dropped.
        :param trace_logfile: EVENT_TRACE_LOGFILE structure.
        """
        self.trace_handle = None
        self.process_thread = None
        self.logger_name = logger_name
        self.end_capture = threading.Event()
        self.event_callback = event_callback
        self.vfield_length = None
        self.index = 0
        self.task_name_filters = task_name_filters if task_name_filters else []
        self.event_id_filters = event_id_filters if event_id_filters else []
        self.providers_event_id_filters = providers_event_id_filters if providers_event_id_filters else {}
        self.callback_data_flag = callback_data_flag if not callback_data_flag else self.check_callback_flag(callback_data_flag)  # NOQA
        self.callback_wait_time = callback_wait_time

        self.pid_whitelist = set(pid_whitelist) if pid_whitelist else set()
        self.pid_blacklist = set(pid_blacklist) if pid_blacklist else set()

        # check if the logger name is "NT Kernel Logger"
        self.kernel_trace = False
        if logger_name.lower() == et.KERNEL_LOGGER_NAME_LOWER:
            self.kernel_trace = True

        if not trace_logfile:
            # Construct the EVENT_TRACE_LOGFILE structure
            self.trace_logfile = et.EVENT_TRACE_LOGFILE()
            self.trace_logfile.ProcessTraceMode = (ec.PROCESS_TRACE_MODE_REAL_TIME | ec.PROCESS_TRACE_MODE_EVENT_RECORD)
            self.trace_logfile.LoggerName = logger_name
        else:
            self.trace_logfile = trace_logfile

        if not self.trace_logfile.EventRecordCallback and \
           self.trace_logfile.ProcessTraceMode & (ec.PROCESS_TRACE_MODE_REAL_TIME | ec.PROCESS_TRACE_MODE_EVENT_RECORD):
            self.trace_logfile.EventRecordCallback = et.EVENT_RECORD_CALLBACK(self._processEvent)

    def add_pid_whitelist(self, pid):
        self.pid_whitelist.add(pid)

    def remove_pid_whitelist(self, pid):
        self.pid_whitelist.discard(pid)

    def reset_whitelist(self):
        self.pid_whitelist = set()

    def add_pid_blacklist(self, pid):
        self.pid_blacklist.add(pid)

    def remove_pid_blacklist(self, pid):
        self.pid_blacklist.discard(pid)

    def reset_blacklist(self):
        self.pid_blacklist = set()

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self):
        """
        Starts a trace consumer.

        :return: Returns True on Success or False on Failure
        """
        self.trace_handle = et.OpenTraceW(ct.byref(self.trace_logfile))
        if self.trace_handle == et.INVALID_PROCESSTRACE_HANDLE:
            raise ct.WinError()

        # For whatever reason, the restype is ignored
        self.trace_handle = et.TRACEHANDLE(self.trace_handle)
        self.process_thread = threading.Thread(target=self._run, args=(self.trace_handle, self.end_capture))
        self.process_thread.daemon = True
        self.process_thread.start()

    def stop(self):
        """
        Stops a trace consumer.

        :return: Returns True on Success or False on Failure
        """
        # Signal to the thread that we are reading to stop processing events.
        self.end_capture.set()

        # Call CloseTrace to cause ProcessTrace to return (unblock)
        et.CloseTrace(self.trace_handle)

        # If ProcessThread is actively parsing an event, we want to give it a chance to finish
        # before pulling the rug out from underneath it.
        self.process_thread.join()

    @staticmethod
    def check_callback_flag(flag):
        """
        Checks callback flags.

        :return: Returns flags on success, on failure raises exception
        """
        flags = [RETURN_RAW_DATA_ONLY,
                 RETURN_RAW_DATA_ON_ERROR,
                 RETURN_ONLY_RAW_DATA_ON_ERROR,
                 RETURN_RAW_UNFORMATTED_DATA]
        if flag not in flags:
            raise Exception('Callback flag value {:d} passed into EventConsumer is invalid'.format(flag))
        return flag

    @staticmethod
    def _run(trace_handle, end_capture):
        """
        Because ProcessTrace() blocks, this function is used to spin off new threads.

        :param trace_handle: The handle for the trace consumer that we want to begin processing.
        :param end_capture: A callback function which determines what should be done with the results.
        :return: Does not return a value.
        """
        while True:
            if tdh.ERROR_SUCCESS != et.ProcessTrace(ct.byref(trace_handle), 1, None, None):
                end_capture.set()

            if end_capture.isSet():
                break

    @staticmethod
    def _getEventInformation(record):
        """
        Initially we are handed an EVENT_RECORD structure. While this structure technically contains
        all of the information necessary, TdhGetEventInformation parses the structure and simplifies it
        so we can more effectively parse and handle the various fields.

        :param record: The EventRecord structure for the event we are parsing
        :return: Returns a pointer to a TRACE_EVENT_INFO structure or None on error.
        """
        info = ct.POINTER(tdh.TRACE_EVENT_INFO)()
        buffer_size = wt.DWORD()

        # Call TdhGetEventInformation once to get the required buffer size and again to actually populate the structure.
        status = tdh.TdhGetEventInformation(record, 0, None, None, ct.byref(buffer_size))
        if tdh.ERROR_INSUFFICIENT_BUFFER == status:
            info = ct.cast((ct.c_byte * buffer_size.value)(), ct.POINTER(tdh.TRACE_EVENT_INFO))
            status = tdh.TdhGetEventInformation(record, 0, None, info, ct.byref(buffer_size))

        if tdh.ERROR_SUCCESS != status:
            raise ct.WinError(status)

        return info

    @staticmethod
    def _getArraySize(record, info, event_property):
        """
        Some of the properties encountered when parsing represent an array of values. This function
        will retrieve the size of the array.

        :param record: The EventRecord structure for the event we are parsing
        :param info: The TraceEventInfo structure for the event we are parsing
        :param event_property: The EVENT_PROPERTY_INFO structure for the TopLevelProperty of the event we are parsing
        :return: Returns a DWORD representing the size of the array or None on error.
        """
        event_property_array = ct.cast(info.contents.EventPropertyInfoArray, ct.POINTER(tdh.EVENT_PROPERTY_INFO))
        flags = event_property.Flags

        if flags & tdh.PropertyParamCount:
            data_descriptor = tdh.PROPERTY_DATA_DESCRIPTOR()
            j = event_property.epi_u2.countPropertyIndex
            property_size = wt.DWORD()
            count = wt.DWORD()

            data_descriptor.PropertyName = info + event_property_array[j].NameOffset
            data_descriptor.ArrayIndex = MAX_UINT

            status = tdh.TdhGetPropertySize(record, 0, None, 1, ct.byref(data_descriptor), ct.byref(property_size))
            if tdh.ERROR_SUCCESS != status:
                raise ct.WinError(status)

            status = tdh.TdhGetProperty(record, 0, None, 1, ct.byref(data_descriptor), property_size, ct.byref(count))
            if tdh.ERROR_SUCCESS != status:
                raise ct.WinError(status)
            return count

        if flags & tdh.PropertyParamFixedCount:
            raise ETWException('PropertyParamFixedCount not supported')

        return event_property.epi_u2.count

    @staticmethod
    def _getPropertyLength(record, info, event_property):
        """
        Each property encountered when parsing the top level property has an associated length. If the
        length is available, retrieve it here. In some cases, the length is 0. This can signify that
        we are dealing with a variable length field such as a structure, an IPV6 data, or a string.

        :param record: The EventRecord structure for the event we are parsing
        :param info: The TraceEventInfo structure for the event we are parsing
        :param event_property: The EVENT_PROPERTY_INFO structure for the TopLevelProperty of the event we are parsing
        :return: Returns the length of the property as a c_ulong() or None on error
        """
        flags = event_property.Flags

        if flags & tdh.PropertyParamLength:
            data_descriptor = tdh.PROPERTY_DATA_DESCRIPTOR()
            event_property_array = ct.cast(info.contents.EventPropertyInfoArray, ct.POINTER(tdh.EVENT_PROPERTY_INFO))
            j = wt.DWORD(event_property.epi_u3.length)
            property_size = ct.c_ulong()
            length = wt.DWORD()

            # Setup the PROPERTY_DATA_DESCRIPTOR structure
            data_descriptor.PropertyName = (ct.cast(info, ct.c_voidp).value + event_property_array[j.value].NameOffset)
            data_descriptor.ArrayIndex = MAX_UINT

            status = tdh.TdhGetPropertySize(record, 0, None, 1, ct.byref(data_descriptor), ct.byref(property_size))
            if tdh.ERROR_SUCCESS != status:
                raise ct.WinError(status)

            status = tdh.TdhGetProperty(record,
                                        0,
                                        None,
                                        1,
                                        ct.byref(data_descriptor),
                                        property_size,
                                        ct.cast(ct.byref(length), ct.POINTER(ct.c_byte)))
            if tdh.ERROR_SUCCESS != status:
                raise ct.WinError(status)
            return length.value

        in_type = event_property.epi_u1.nonStructType.InType
        out_type = event_property.epi_u1.nonStructType.OutType

        # This is a special case in which the input and output types dictate the size
        if (in_type == tdh.TDH_INTYPE_BINARY) and (out_type == tdh.TDH_OUTTYPE_IPV6):
            return ct.sizeof(ia.IN6_ADDR)

        return event_property.epi_u3.length

    @staticmethod
    def _getMapInfo(record, info, event_property):
        """
        When parsing a field in the event property structure, there may be a mapping between a given
        name and the structure it represents. If it exists, we retrieve that mapping here.

        Because this may legitimately return a NULL value we return a tuple containing the success or
        failure status as well as either None (NULL) or an EVENT_MAP_INFO pointer.

        :param record: The EventRecord structure for the event we are parsing
        :param info: The TraceEventInfo structure for the event we are parsing
        :param event_property: The EVENT_PROPERTY_INFO structure for the TopLevelProperty of the event we are parsing
        :return: A tuple of the map_info structure and boolean indicating whether we succeeded or not
        """
        map_name = rel_ptr_to_str(info, event_property.epi_u1.nonStructType.MapNameOffset)
        map_size = wt.DWORD()
        map_info = ct.POINTER(tdh.EVENT_MAP_INFO)()

        status = tdh.TdhGetEventMapInformation(record, map_name, None, ct.byref(map_size))
        if tdh.ERROR_INSUFFICIENT_BUFFER == status:
            map_info = ct.cast((ct.c_char * map_size.value)(), ct.POINTER(tdh.EVENT_MAP_INFO))
            status = tdh.TdhGetEventMapInformation(record, map_name, map_info, ct.byref(map_size))

        if tdh.ERROR_SUCCESS == status:
            return map_info, True

        # ERROR_NOT_FOUND is actually a perfectly acceptable status
        if tdh.ERROR_NOT_FOUND == status:
            return None, True

        # We actually failed.
        raise ct.WinError()

    def _unpackSimpleType(self, record, info, event_property):
        """
        This method handles dumping all simple types of data (i.e., non-struct types).

        :param record: The EventRecord structure for the event we are parsing
        :param info: The TraceEventInfo structure for the event we are parsing
        :param event_property: The EVENT_PROPERTY_INFO structure for the TopLevelProperty of the event we are parsing
        :return: Returns a key-value pair as a dictionary. If we fail, the dictionary is {}
        """
        # Get the EVENT_MAP_INFO, if it is present.
        map_info, success = self._getMapInfo(record, info, event_property)
        if not success:
            return {}

        # Get the length of the value of the property we are dealing with.
        property_length = self._getPropertyLength(record, info, event_property)
        if property_length is None:
            return {}
        # The version of the Python interpreter may be different than the system architecture.
        if record.contents.EventHeader.Flags & ec.EVENT_HEADER_FLAG_32_BIT_HEADER:
            ptr_size = 4
        else:
            ptr_size = 8

        name_field = rel_ptr_to_str(info, event_property.NameOffset)
        if property_length == 0 and self.vfield_length is not None:
            if self.vfield_length == 0:
                self.vfield_length = None
                return {name_field: None}

            # If vfield_length isn't 0, we should be able to parse the property.
            property_length = self.vfield_length

        # After calling the TdhFormatProperty function, use the UserDataConsumed parameter value to set the new values
        # of the UserData and UserDataLength parameters (Subtract UserDataConsumed from UserDataLength and use
        # UserDataLength to increment the UserData pointer).

        # All of the variables needed to actually use TdhFormatProperty retrieve the value
        user_data = record.contents.UserData + self.index
        user_data_remaining = record.contents.UserDataLength - self.index

        # if there is no data remaining then return
        if user_data_remaining <= 0:
            logger.warning('No more user data left, returning none for field {:s}'.format(name_field))
            return {name_field: None}

        in_type = event_property.epi_u1.nonStructType.InType
        out_type = event_property.epi_u1.nonStructType.OutType
        formatted_data_size = wt.DWORD()
        formatted_data = wt.LPWSTR()
        user_data_consumed = ct.c_ushort()

        status = tdh.TdhFormatProperty(info,
                                       map_info,
                                       ptr_size,
                                       in_type,
                                       out_type,
                                       ct.c_ushort(property_length),
                                       user_data_remaining,
                                       ct.cast(user_data, ct.POINTER(ct.c_byte)),
                                       ct.byref(formatted_data_size),
                                       None,
                                       ct.byref(user_data_consumed))

        if status == tdh.ERROR_INSUFFICIENT_BUFFER:
            formatted_data = ct.cast((ct.c_char * formatted_data_size.value)(), wt.LPWSTR)
            status = tdh.TdhFormatProperty(info,
                                           map_info,
                                           ptr_size,
                                           in_type,
                                           out_type,
                                           ct.c_ushort(property_length),
                                           user_data_remaining,
                                           ct.cast(user_data, ct.POINTER(ct.c_byte)),
                                           ct.byref(formatted_data_size),
                                           formatted_data,
                                           ct.byref(user_data_consumed))

        if status != tdh.ERROR_SUCCESS:
            # We can handle this error and still capture the data.
            logger.warning('Failed to get data field data for {:s}, incrementing by reported size'.format(name_field))
            self.index += property_length
            return {name_field: None}

        # Increment where we are in the user data segment that we are parsing.
        self.index += user_data_consumed.value

        if name_field.lower().endswith('length'):
            try:
                self.vfield_length = int(formatted_data.value, 10)
            except ValueError:
                logger.warning('Setting vfield_length to None')
                self.vfield_length = None

        data = formatted_data.value
        # Convert the formatted data if necessary
        if out_type in tdh.TDH_CONVERTER_LOOKUP and type(data) != tdh.TDH_CONVERTER_LOOKUP[out_type]:
            data = tdh.TDH_CONVERTER_LOOKUP[out_type](data)

        return {name_field: data}

    def _parseExtendedData(self, record):
        """
        This method handles dumping all extended data from the record

        :param record: The EventRecord structure for the event we are parsing
        :return: Returns a key-value pair as a dictionary.
        """
        result = {}
        for i in range(record.contents.ExtendedDataCount):
            ext_type = record.contents.ExtendedData[i].ExtType
            data_ptr = record.contents.ExtendedData[i].DataPtr
            data_size = record.contents.ExtendedData[i].DataSize
            try:
                if ext_type == ec.EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID:
                    d = ct.cast(data_ptr, ct.POINTER(ec.EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID))
                    result['RelatedActivityID'] = str(d.contents.RelatedActivityId)
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_SID:
                    buff = ct.create_string_buffer(data_size)
                    ct.memmove(buff, data_ptr, data_size)
                    sid_string = wt.LPWSTR()
                    res = et.ConvertSidToStringSidW(ct.cast(buff, ct.c_void_p), ct.byref(sid_string))
                    if res > 0:
                        result['SID'] = str(sid_string.value)
                        et.LocalFree(sid_string)
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_TS_ID:
                    d = ct.cast(data_ptr, ct.POINTER(ec.EVENT_EXTENDED_ITEM_TS_ID))
                    result['TSID'] = d.contents.SessionId
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_INSTANCE_INFO:
                    d = ct.cast(data_ptr, ct.POINTER(ec.EVENT_EXTENDED_ITEM_INSTANCE))
                    instance = {
                        'InstanceId': d.contents.InstanceId,
                        'ParentInstanceId': d.contents.ParentInstanceId,
                        'ParentGuid': str(d.contents.ParentGuid)
                    }
                    result['InstanceInfo'] = instance
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_STACK_TRACE32:
                    nb_address = int((data_size - ct.sizeof(ct.c_ulonglong)) / ct.sizeof(ct.c_ulong))
                    d = ct.cast(data_ptr, ct.POINTER(ec.EVENT_EXTENDED_ITEM_STACK_TRACE32))
                    match_id = d.contents.MatchId
                    addr_buf = ct.cast(ct.addressof(d.contents.Address), ct.POINTER((ct.c_ulong * nb_address)))
                    addr_list = []
                    for j in range(nb_address):
                        addr_list.append(addr_buf.contents[j])
                    result['StackTrace32'] = {
                        'MatchId': match_id,
                        'Address': addr_list
                    }
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_STACK_TRACE64:
                    nb_address = int((data_size - ct.sizeof(ct.c_ulonglong)) / ct.sizeof(ct.c_ulonglong))
                    d = ct.cast(data_ptr, ct.POINTER(ec.EVENT_EXTENDED_ITEM_STACK_TRACE64))
                    match_id = d.contents.MatchId
                    addr_buf = ct.cast(ct.addressof(d.contents.Address), ct.POINTER((ct.c_ulonglong * nb_address)))
                    addr_list = []
                    for j in range(nb_address):
                        addr_list.append(addr_buf.contents[j])
                    result['StackTrace64'] = {
                        'MatchId': match_id,
                        'Address': addr_list
                    }
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_PEBS_INDEX:
                    d = ct.cast(data_ptr, ct.POINTER(ec.EVENT_EXTENDED_ITEM_PEBS_INDEX))
                    result['PebsIndex'] = d.contents.PebsIndex
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_PMC_COUNTERS:
                    nb_counters = int(data_size / ct.sizeof(ct.c_ulonglong))
                    counters_buf = ct.cast(data_ptr, ct.POINTER((ct.c_ulonglong * nb_counters)))
                    counters_list = []
                    for j in range(nb_counters):
                        counters_list.append(counters_buf.contents[j])
                    result['PMCCounters'] = counters_list
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_PSM_KEY:
                    pass
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_EVENT_KEY:
                    d = ct.cast(data_ptr, ct.POINTER(ec.EVENT_EXTENDED_ITEM_EVENT_KEY))
                    result['EventKey'] = d.contents.Key
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL:
                    pass
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_PROV_TRAITS:
                    pass
                elif ext_type == ec.EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY:
                    d = ct.cast(data_ptr, ct.POINTER(ec.EVENT_EXTENDED_ITEM_PROCESS_START_KEY))
                    result['StartKey'] = d.contents.ProcessStartKey
            except Exception as e:
                logger.warning('Extended data parse error (type %d, size %d) : %s' % (ext_type, data_size, str(e)))
        return result

    def _unpackComplexType(self, record, info, event_property):
        """
        A complex type (e.g., a structure with sub-properties) can only contain simple types. Loop over all
        sub-properties and dump the property name and value.

        :param record: The EventRecord structure for the event we are parsing
        :param info: The TraceEventInfo structure for the event we are parsing
        :param event_property: The EVENT_PROPERTY_INFO structure for the TopLevelProperty of the event we are parsing
        :return: A dictionary of the property and value for the event we are parsing
        """
        out = {}

        array_size = self._getArraySize(record, info, event_property)
        if array_size is None:
            return {}

        for _ in range(array_size):
            start_index = event_property.epi_u1.structType.StructStartIndex
            last_member = start_index + event_property.epi_u1.structType.NumOfStructMembers

            for j in range(start_index, last_member):
                # Because we are no longer dealing with the TopLevelProperty, we need to get the event_property_array
                # again so we can get the EVENT_PROPERTY_INFO structure of the sub-property we are currently parsing.
                event_property_array = ct.cast(info.contents.EventPropertyInfoArray,
                                               ct.POINTER(tdh.EVENT_PROPERTY_INFO))

                key, value = self._unpackSimpleType(record, info, event_property_array[j])
                if key is None and value is None:
                    break

                out[key] = value

        return out

    def _processEvent(self, record):
        """
        This is a callback function that fires whenever an event needs handling. It iterates through the structure to
        parse the properties of each event. If a user defined callback is specified it then passes the parsed data to
        it.


        :param record: The EventRecord structure for the event we are parsing
        :return: Nothing
        """

        if self.callback_wait_time:
            time.sleep(self.callback_wait_time)

        parsed_data = {}
        record_parse_error = True
        field_parse_error = False

        if self.callback_data_flag == RETURN_RAW_UNFORMATTED_DATA:
            event_id = 0
            out = record
        else:
            # event ID is in "Opcode" field in kernel events, Id is always 0
            if self.kernel_trace:
                event_id = record.contents.EventHeader.EventDescriptor.Opcode
            else:
                event_id = record.contents.EventHeader.EventDescriptor.Id
            if self.event_id_filters and event_id not in self.event_id_filters:
                return
            # set task name to provider guid for the time being
            task_name = str(record.contents.EventHeader.ProviderId)

            # filter event ID in provider if requested (otherwise, we handle all events)
            task_name_upper = task_name.upper()
            if task_name_upper in self.providers_event_id_filters and event_id not in self.providers_event_id_filters[task_name_upper]:
                return

            pid = record.contents.EventHeader.ProcessId
            # if we have a whitelist set, keep only events for those PIDs
            # don't look at blacklist in that case
            if self.pid_whitelist:
                if pid not in self.pid_whitelist:
                    return
            # no whitelist, check for a blacklist
            else:
                if self.pid_blacklist and pid in self.pid_blacklist:
                    return

            # add all header fields from EVENT_HEADER structure
            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa363759(v=vs.85).aspx
            out = {'EventHeader': {
                'Size': record.contents.EventHeader.Size,
                'HeaderType': record.contents.EventHeader.HeaderType,
                'Flags': record.contents.EventHeader.Flags,
                'EventProperty': record.contents.EventHeader.EventProperty,
                'ThreadId': record.contents.EventHeader.ThreadId,
                'ProcessId': record.contents.EventHeader.ProcessId,
                'TimeStamp': record.contents.EventHeader.TimeStamp,
                'ProviderId': task_name,
                'EventDescriptor': {'Id': event_id,
                                    'Version': record.contents.EventHeader.EventDescriptor.Version,
                                    'Channel': record.contents.EventHeader.EventDescriptor.Channel,
                                    'Level': record.contents.EventHeader.EventDescriptor.Level,
                                    'Opcode': record.contents.EventHeader.EventDescriptor.Opcode,
                                    'Task': record.contents.EventHeader.EventDescriptor.Task,
                                    'Keyword':
                                        record.contents.EventHeader.EventDescriptor.Keyword},
                'KernelTime': record.contents.EventHeader.KernelTime,
                'UserTime': record.contents.EventHeader.UserTime,
                'ActivityId': str(record.contents.EventHeader.ActivityId)},
                'Task Name': task_name}

            if self.callback_data_flag != RETURN_RAW_DATA_ONLY:
                try:
                    info = self._getEventInformation(record)

                    # Some events do not have an associated task_name value. In this case, we should use the provider
                    # name instead.
                    if info.contents.TaskNameOffset == 0:
                        task_name = rel_ptr_to_str(info, info.contents.ProviderNameOffset)
                    else:
                        task_name = rel_ptr_to_str(info, info.contents.TaskNameOffset)

                    task_name = task_name.strip().upper()

                    # Add a description for the event, if present
                    if info.contents.EventMessageOffset:
                        description = rel_ptr_to_str(info, info.contents.EventMessageOffset)
                    else:
                        description = ''

                    # Windows 7 does not support predicate filters. Instead, we use a whitelist to filter things on the
                    # consumer.
                    if self.task_name_filters and task_name not in self.task_name_filters:
                        return

                    user_data = record.contents.UserData
                    if user_data is None:
                        user_data = 0

                    end_of_user_data = user_data + record.contents.UserDataLength
                    self.index = 0
                    self.vfield_length = None
                    property_array = ct.cast(info.contents.EventPropertyInfoArray, ct.POINTER(tdh.EVENT_PROPERTY_INFO))

                    for i in range(info.contents.TopLevelPropertyCount):
                        # If the user_data is the same value as the end_of_user_data, we are ending with a 0-length
                        # field. Though not documented, this is completely valid.
                        if user_data == end_of_user_data:
                            break

                        # Determine whether we are processing a simple type or a complex type and act accordingly
                        if property_array[i].Flags & tdh.PropertyStruct:
                            field = self._unpackComplexType(record, info, property_array[i])
                        else:
                            field = self._unpackSimpleType(record, info, property_array[i])

                        if field == {} or None in field.values():
                            field_parse_error = True
                        parsed_data.update(field)

                    # Add the description field in
                    parsed_data['Description'] = description
                    parsed_data['Task Name'] = task_name
                    # Add ExtendedData if any
                    if record.contents.EventHeader.Flags & ec.EVENT_HEADER_FLAG_EXTENDED_INFO:
                        parsed_data['EventExtendedData'] = self._parseExtendedData(record)

                    record_parse_error = False
                except Exception as e:
                    logger.warning('Unable to parse event: {}'.format(e))

        try:
            if self.callback_data_flag == RETURN_RAW_DATA_ONLY or \
                    ((self.callback_data_flag == RETURN_RAW_DATA_ON_ERROR or
                      self.callback_data_flag == RETURN_ONLY_RAW_DATA_ON_ERROR) and
                     (field_parse_error or record_parse_error)):
                out['UserData'] = b''.join([ct.cast(record.contents.UserData + i, wt.PBYTE).contents
                                            for i in range(record.contents.UserDataLength)])

            if (self.callback_data_flag == RETURN_ONLY_RAW_DATA_ON_ERROR and field_parse_error is False) or \
               self.callback_data_flag == RETURN_RAW_DATA_ON_ERROR or self.callback_data_flag == 0:

                out.update(parsed_data)

            # Call the user's specified callback function
            if self.event_callback:
                self.event_callback((event_id, out))

        except Exception as e:
            logger.error('Exception during callback: {}'.format(e))
            logger.error(traceback.format_exc())


class ETW:
    """
    Serves as a base class for each capture trace type.
    """

    def __init__(
            self,
            session_name=None,
            ring_buf_size=1024,
            max_str_len=1024,
            min_buffers=0,
            max_buffers=0,
            event_callback=None,
            task_name_filters=None,
            properties=None,
            providers=None,
            ignore_exists_error=True,
            event_id_filters=None,
            providers_event_id_filters=None,
            pid_whitelist=None,
            pid_blacklist=None,
            callback_data_flag=0,
            callback_wait_time=0.0,
            trace_logfile=None):
        """
        Initializes an instance of the ETW class. The default buffer parameters represent a very typical use case and
        should not be overridden unless the user knows what they are doing.

        :param session_name: Session name for the ETW capture session
        :param ring_buf_size: The size of the ring buffer used for capturing events.
        :param max_str_len: The maximum length of the strings the proceed the structure.
                            Unless you know what you are doing, do not modify this value.
        :param min_buffers: The minimum number of buffers for an event tracing session.
                            Unless you know what you are doing, do not modify this value.
        :param max_buffers: The maximum number of buffers for an event tracing session.
                            Unless you know what you are doing, do not modify this value.
        :param event_callback: An optional parameter allowing the caller to specify a callback function for each event
                               that is parsed.
        :param task_name_filters: List of filters to apply to the ETW capture
        :param properties: An instance of TraceProperties class to use for the capture
        :param providers: A list of ProviderInfo class instances that will be used for the capture session. Do not reuse
                          providers.
        :param ignore_exists_error: If true (default), the library will ignore an ERROR_ALREADY_EXISTS on the
                                    EventProvider start.
        :param event_id_filters: List of event ids to filter on.
        :param providers_event_id_filters: Dict of provider/ list of ids to filter on.
        :param pid_whitelist: List of PID for which we want to receive events (only events for those PIDs will be processed).
        :param pid_blacklist: List of PID for which we don't want to receive events (events for all PIDs except those will be processed).
        :param callback_data_flag: Determines how to format data passed into callback.
        :param callback_wait_time: Time callback will sleep when called. If used, this may cause events to be dropped.
        :param trace_logfile: EVENT_TRACE_LOGFILE structure to be passed to the consumer.
        """

        if task_name_filters is None:
            self.task_name_filters = []
        else:
            self.task_name_filters = task_name_filters

        if event_id_filters is None:
            self.event_id_filters = []
        else:
            self.event_id_filters = event_id_filters

        if providers_event_id_filters is None:
            self.providers_event_id_filters = {}
        else:
            self.providers_event_id_filters = providers_event_id_filters

        if pid_whitelist is None:
            self.pid_whitelist = set()
        else:
            self.pid_whitelist = set(pid_whitelist)

        if pid_blacklist is None:
            self.pid_blacklist = set()
        else:
            self.pid_blacklist = set(pid_blacklist)

        if providers is None:
            self.providers = []
        else:
            self.providers = providers

        if properties is None:
            self.properties = TraceProperties(ring_buf_size,
                                              max_str_len,
                                              min_buffers,
                                              max_buffers)
        else:
            self.properties = properties

        if session_name is None:
            self.session_name = '{:s}'.format(str(uuid.uuid4()))
        else:
            self.session_name = session_name

        self.provider = None
        self.consumer = None
        self.running = False
        self.event_callback = event_callback
        self.ignore_exists_error = ignore_exists_error
        self.callback_data_flag = callback_data_flag
        self.callback_wait_time = callback_wait_time
        self.trace_logfile = trace_logfile

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc, ex, tb):
        self.stop()

    def start(self):
        """
        Starts the providers and the consumers for capturing data using ETW.

        :return: Does not return anything.
        """

        if self.provider is None:
            self.provider = EventProvider(self.session_name, self.properties, self.providers)

        if self.running is False:
            self.running = True
            try:
                self.provider.start()
            except WindowsError as wex:
                if (wex.winerror == tdh.ERROR_ALREADY_EXISTS and not self.ignore_exists_error) or \
                   wex.winerror != tdh.ERROR_ALREADY_EXISTS:
                    raise wex

            # Start the consumer
            self.consumer = EventConsumer(self.session_name,
                                          self.event_callback,
                                          self.task_name_filters,
                                          self.event_id_filters,
                                          self.providers_event_id_filters,
                                          self.pid_whitelist,
                                          self.pid_blacklist,
                                          self.callback_data_flag,
                                          self.callback_wait_time,
                                          self.trace_logfile)
            self.consumer.start()

    def stop(self):
        """
        Stops the current consumer and provider.

        :return: Does not return anything.
        """

        if self.provider:
            self.running = False
            self.provider.stop()
            self.consumer.stop()

    def add_provider(self, provider):
        '''
        Adds a ProviderInfo instance to the capture

        :param provider: ProviderInfo class instance to add
        :return: Does not return anything
        '''

        self.providers.append(provider)

    def query(self):
        props = TraceProperties()
        et.ControlTraceW(et.TRACEHANDLE(0),
                         self.session_name,
                         props.get(),
                         et.EVENT_TRACE_CONTROL_QUERY)
        return props.get().contents

    def update(self, trace_properties):
        '''
        Update the trace session properties on the fly

        :param trace_properties: TraceProperties class instance to use
        :return: Does not return anything
        '''
        et.ControlTraceW(et.TRACEHANDLE(0),
                         self.session_name,
                         trace_properties.get(),
                         et.EVENT_TRACE_CONTROL_UPDATE)

    def control_stop(self, trace_properties):
        '''
        stop the trace session properties on the fly

        :param trace_properties: TraceProperties class instance to use
        :return: Does not return anything
        '''
        et.ControlTraceW(et.TRACEHANDLE(0),
                         self.session_name,
                         trace_properties.get(),
                         et.EVENT_TRACE_CONTROL_STOP)

    def add_pid_whitelist(self, pid):
        '''
        add a PID to the whitelisted list of PIDs

        :param pid: pid to whitelist
        :return: Does not return anything
        '''
        # keep in our current list
        self.pid_whitelist.add(pid)
        # if consumer is started, update the list in the consumer
        if self.consumer:
            self.consumer.add_pid_whitelist(pid)

    def remove_pid_whitelist(self, pid):
        '''
        remove a PID from the whitelisted list of PIDs

        :param pid: pid to un-whitelist
        :return: Does not return anything
        '''
        # remove from our list
        self.pid_whitelist.discard(pid)
        # if consumer is started, update the list in the consumer
        if self.consumer:
            self.consumer.remove_pid_whitelist(pid)

    def reset_whitelist(self):
        '''
        reset the list of whitelisted PIDs

        :return: Does not return anything
        '''
        self.pid_whitelist = set()
        # if consumer is started, update the list in the consumer
        if self.consumer:
            self.consumer.reset_whitelist()

    def add_pid_blacklist(self, pid):
        '''
        add a PID to the blacklisted list of PIDs

        :param pid: pid to blacklist
        :return: Does not return anything
        '''
        # keep in our current list
        self.pid_blacklist.add(pid)
        # if consumer is started, update the list in the consumer
        if self.consumer:
            self.consumer.add_pid_blacklist(pid)

    def remove_pid_blacklist(self, pid):
        '''
        remove a PID from the blacklisted list of PIDs

        :param pid: pid to un-blacklist
        :return: Does not return anything
        '''
        # remove from our list
        self.pid_blacklist.discard(pid)
        # if consumer is started, update the list in the consumer
        if self.consumer:
            self.consumer.remove_pid_blacklist(pid)

    def reset_blacklist(self):
        '''
        reset the list of blacklisted PIDs

        :return: Does not return anything
        '''
        self.pid_blacklist = set()
        # if consumer is started, update the list in the consumer
        if self.consumer:
            self.consumer.reset_blacklist()


class ProviderInfo:
    """ Container class for provider info """
    def __init__(self, name, guid, level=et.TRACE_LEVEL_INFORMATION, any_keywords=None, all_keywords=None, params=None):
        """
        Initializes an instance of the ProviderInfo class.

        :param name: Name of the provider.
        :param guid: GUID of the provider.
        :param level: The info level for the provider.
        :param any_keywords: list of any keywords to add for provider, or a bitmask
        :param all_keywords: list of all keywords to add for provider, or a bitmask
                            Unless you know what you are doing, do not modify this value.
        :param params: pointer to optional ENABLE_TRACE_PARAMETERS structure
        """
        self.name = name
        self.guid = guid
        self.level = level
        if type(any_keywords) is list or any_keywords is None:
            self.any_bitmask = get_keywords_bitmask(guid, any_keywords)
        else:
            self.any_bitmask = any_keywords

        if type(all_keywords) is list or all_keywords is None:
            self.all_bitmask = get_keywords_bitmask(guid, all_keywords)
        else:
            self.all_bitmask = all_keywords
        self.params = params

    def __eq__(self, other):
        result = True
        self_dict = self.__dict__
        other_dict = other.__dict__
        self_params = self_dict.pop('params')
        other_params = other_dict.pop('params')

        if self_params:
            if other_params:
                for field in self_params.contents._fields_:
                    attr_name = field[0]
                    a, b = getattr(self_params.contents, attr_name), getattr(other_params.contents, attr_name)
                    is_desc = isinstance(a, ct.POINTER(ep.EVENT_FILTER_DESCRIPTOR))
                    if is_desc is True:
                        if a:
                            for desc_field in a.contents._fields_:
                                desc_attr_name = desc_field[0]
                                a_desc, b_desc = getattr(a.contents, desc_attr_name),\
                                    getattr(b.contents, desc_attr_name)
                                if a_desc != b_desc:
                                    result = False
                                    break
                    else:
                        if a != b:
                            result = False
                            break
            else:
                result = False

        result = self_dict == other_dict and result
        self_dict['params'] = self_params
        other_dict['params'] = other_params
        return result


class ProviderParameters:
    """
    The ProviderParameters class represents the ENABLE_TRACE_PARAMETERS structure. The class wraps
    this structure to make it easier to interact with.
    """

    def __init__(self, event_property, event_filters):
        """
        Initializes an ENABLE_TRACE_PARAMETERS structure.

        :param event_property: Property to enable.
                         See https://msdn.microsoft.com/en-us/library/windows/desktop/dd392306(v=vs.85).aspx
        :param event_filters: List of EVENT_FILTER_DESCRIPTOR structures
        """

        self._props = ct.pointer(et.ENABLE_TRACE_PARAMETERS())

        filter_buf_size = ct.sizeof(ep.EVENT_FILTER_DESCRIPTOR) * len(event_filters)
        # noinspection PyCallingNonCallable
        filter_buf = (ct.c_char * filter_buf_size)()
        # copy contents to buffer
        for i in range(len(event_filters)):
            ct.memmove(ct.cast(ct.addressof(filter_buf) + (ct.sizeof(ep.EVENT_FILTER_DESCRIPTOR) * i), ct.c_void_p),
                       ct.byref(event_filters[i]),
                       ct.sizeof(ep.EVENT_FILTER_DESCRIPTOR))

        self._props.contents.Version = et.ENABLE_TRACE_PARAMETERS_VERSION_2
        self._props.contents.EnableProperty = event_property
        self._props.contents.ControlFlags = 0
        self._props.contents.EnableFilterDesc = ct.cast(ct.pointer(filter_buf), ct.POINTER(ep.EVENT_FILTER_DESCRIPTOR))
        self._props.contents.FilterDescCount = len(event_filters)

    def __eq__(self, other):
        for field in self.get().contents._fields_:
            attr_name = field[0]
            a, b = getattr(self.get().contents, attr_name), getattr(other.get().contents, attr_name)
            is_desc = isinstance(a, ct.POINTER(ep.EVENT_FILTER_DESCRIPTOR))
            if is_desc is True:
                if a:
                    for desc_field in a.contents._fields_:
                        desc_attr_name = desc_field[0]
                        a_desc, b_desc = getattr(a.contents, desc_attr_name), getattr(b.contents, desc_attr_name)
                        if a_desc != b_desc:
                            return False
            else:
                if a != b:
                    return False
        return True

    def get(self):
        """
        This class wraps the construction of a struct for ctypes. As a result, in order to properly use it as a ctypes
        structure, you must use the private field _props. To maintain proper encapsulation, this getter is used to
        retrieve this value when needed.

        :return: The _props field needed for using this class as a ctypes EVENT_FILTER_DESCRIPTOR structure.
        """
        return self._props


def get_keywords_bitmask(guid, keywords):
    """
    Queries available keywords of the provider and returns a bitmask of the associated values

    :param guid: The GUID of the ETW provider.
    :param keywords: List of keywords to resolve.
    :return Bitmask of the keyword flags ORed together
    """

    bitmask = 0
    if keywords is None or len(keywords) == 0:
        return bitmask

    # enumerate the keywords for the provider as well as the bitmask values
    provider_info = None
    providers_size = wt.ULONG(0)
    status = tdh.TdhEnumerateProviderFieldInformation(
        ct.byref(guid),
        tdh.EventKeywordInformation,
        provider_info,
        ct.byref(providers_size))

    if status == tdh.ERROR_INSUFFICIENT_BUFFER:

        provider_info = ct.cast((ct.c_char * providers_size.value)(), ct.POINTER(tdh.PROVIDER_FIELD_INFOARRAY))
        status = tdh.TdhEnumerateProviderFieldInformation(
            ct.byref(guid),
            tdh.EventKeywordInformation,
            provider_info,
            ct.byref(providers_size))

    if tdh.ERROR_SUCCESS != status and tdh.ERROR_NOT_FOUND != status:
        raise ct.WinError(status)

    if provider_info:
        field_info_array = ct.cast(provider_info.contents.FieldInfoArray, ct.POINTER(tdh.PROVIDER_FIELD_INFO))
        provider_keywords = {}
        for i in range(provider_info.contents.NumberOfElements):
            provider_keyword = rel_ptr_to_str(provider_info, field_info_array[i].NameOffset)
            provider_keywords[provider_keyword] = field_info_array[i].Value

        for keyword in keywords:
            if keyword in provider_keywords:
                bitmask |= provider_keywords[keyword]

    return bitmask

