# ETW (Event Tracing for Windows)
ETW is a tracing facility that allows a user to log events to a file or buffer. An overview of ETW can be found [here](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363668(v=vs.85).aspx). The basic architecture includes an Provider (Producer), Controller, and a Consumer. The controller defines and controls a capture session. This includes what providers are in the as well as starting and stopping the session. The provider, specified using a GUID (Globally Unique Identifier), logs events to a series of buffers. The Consumer receives messages either from a buffer or a file and processes them in chronological order.

This module is an entirely Python-based ctypes wrapper around the Win32 APIs necessary for for controlling ETW sessions and processing message data. The module is very flexible and can process messages pre or post capture. 

## Usage

To use this module import `etw` and create an instance of the ETW class passing in the GUID of the provider you wish to capture data from. To process data you will need to specify a callback process the data.

<pre>
<code>
import etw


def some_func():
    # define capture GUID
    guid = {'Some Provider': etw.GUID("{11111111-1111-1111-1111-111111111111}")}

    # create instance of ETW class
    job = etw.ETW(guid)

    # run capture
    etw.run('etw', job)
</code>
</pre>


Below is an example using the module to perform a capture using a custom callback.

<pre>
<code>
import time
import etw


def some_func():
    # define capture GUID
    guid = {'Some Provider': etw.GUID("{11111111-1111-1111-1111-111111111111}")}
    # create instance of ETW class
    job = etw.ETW(guid)
    # start capture
    job.start(lambda x: print(x))

    # wait some time
    time.sleep(5)

    # stop capture
    job.stop()
</code>
</pre>

Subclassing is another handy way to define ETW capture classes.

<pre>
<code>
import time
import etw


class MyETW(etw.ETW):

    def __init__(self):
        # define capture GUID
        guid = {'Some Provider': etw.GUID("{11111111-1111-1111-1111-111111111111}")}
        super().__init__(guid)

    def start(self, event_callback=None, task_name_filters=None, ignore_exists_error=True):
        # do pre-capture setup
        self.do_capture_setup()
        super().start(event_callback)

    def stop(self):
        super().stop()
        # do post-capture teardown
        self.do_capture_teardown()

    def do_capture_setup(self):
        # do whatever setup for capture here
        pass

    def do_capture_teardown(self):
        # do whatever for capture teardown here
        pass


def my_capture():
    # instantiate class
    capture = MyETW()
    # start capture
    capture.start(lambda x: print(x))
    # wait some time to capture data
    time.sleep(5)
    # stop capture
    capture.stop()
</code>
</pre>

For more examples see [examples](examples).
