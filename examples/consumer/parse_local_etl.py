import struct
import time
import etw


# consumer a local .etl log file
logger_name = 'eventlog.etl'
index = 1
header_tag = True


def event_callback(data):
    # time convert
    file_time = data[1]['EventHeader']['TimeStamp']
    utc_time_stamp = (file_time - 116444736000000000) // 10000000  # 秒
    data[1]['EventHeader']['TimeStamp'] = time.strftime(
            '%Y-%m-%dT%H:%M:%S', time.localtime(utc_time_stamp))
    global index
    print('Index', index)
    print('EventID:', type(data[0]))                 # int type
    print('ProcessId:', type(data[1]['EventHeader']['ProcessId']))
    print('ThreadId:', type(data[1]['EventHeader']['ThreadId']))
    print('Time:', data[1]['EventHeader']['TimeStamp'])
    print('EventDescriptor', data[1]['EventHeader']['EventDescriptor'])
    print('GUID:', data[1]['Task Name'])

    # parse userData
    if data[0] == 0:
        global header_tag
        if header_tag:
            user_data = extract_header(data[1]['UserData'])
            print('FileHeaderData:', user_data)
    else:
        try:
            print('UserData:', data[1]['UserData'].decode('utf-8'))
        except UnicodeDecodeError:
            pass
    print('')
    index += 1


def extract_header(byte):
    user_data = dict()
    user_data['BufferSize'] = struct.unpack_from('<I', byte, 0)[0]
    user_data['Version'] = struct.unpack_from('<I', byte, 4)[0]
    user_data['ProviderVersion'] = struct.unpack_from('<I', byte, 8)[0]
    user_data['CPUKernelNums'] = struct.unpack_from('<I', byte, 12)[0]
    global header_tag
    header_tag = False
    return user_data


if __name__ == '__main__':
    # Start Parse the file
    with etw.etw.EventConsumer(logger_name, event_callback, [], [], 0x1, True,
                               None):
        pass
