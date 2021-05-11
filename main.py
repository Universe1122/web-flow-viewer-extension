from burp import IBurpExtender               # Required for all extensions
from burp import IMessageEditorTab           # Used to create custom tabs within the Burp HTTP message editors
from burp import IMessageEditorTabFactory    # Provides rendering or editing of HTTP messages, within within the created tab
from burp import IHttpListener
import base64                                # Required to decode Base64 encoded header value
from exceptions_fix import FixBurpExceptions # Used to make the error messages easier to debug
import sys
from java.util import ArrayList;
from threading import Lock

sys.path.append('C:\jython.2.7.1\Lib\site-packages')
import requests


request_filter_Accpet = [
    "image", "css"
]

filter_ContentType = [
    "application/json",     # json
    "text/json",            # json
    "text/x-json",          # json
    "text/html",            # plaintext
    "text/plain",           # plaintext
    "application/xml",       # xml
    "application/xml-external-parsed-entity",   # xml
    "application/xml-dtd",                      # xml
    "application/mathtml+xml",                  # xml
    "application/xslt+xml",                      # xml
    "text/javascript",
    "application/javascript"
    # multipart/form-data `
]



class BurpExtender(IBurpExtender, IHttpListener):
    ''' Implements IBurpExtender for hook into burp and inherit base classes.
     Implement IMessageEditorTabFactory to access createNewInstance.
    '''
    def registerExtenderCallbacks(self, callbacks):
        # required for debugger: https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()

        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        # This method is used to obtain an IExtensionHelpers object, which can be used by the extension to perform numerous useful tasks
        # https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html
        self._helpers = callbacks.getHelpers()
        self._log = ArrayList()
        self._lock = Lock()
        # set our extension name
        callbacks.setExtensionName("Decode Basic Auth")

        # register ourselves as a message editor tab factory
        callbacks.registerHttpListener(self)

        return
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl()))
        self._lock.release()

        
        msg = messageInfo.getResponse()
        analyze = self._helpers.analyzeResponse(msg)
        self._headers = list(analyze.getHeaders())
        
        body = messageInfo.getResponse()[analyze.getBodyOffset():]

        for headers in self._headers:
            if headers.lower().startswith("content-type:"):
                content_type = headers.split(":")[1].lower()
                for ContentTypes in filter_ContentType:
                    if content_type.find(ContentTypes) != -1:
                        index = self._log.size()

                        request_header = list(self._helpers.analyzeRequest(self._log.get(index - 1)._requestResponse.getRequest()).getHeaders())
                        response_header = list(self._helpers.analyzeResponse(self._log.get(index - 1)._requestResponse.getResponse()).getHeaders())
                        requests.post("http://localhost:5000/log", data={'request_header' : "\n".join(request_header), 'response_header' : "\n".join(response_header)})
                        # print(self._helpers.bytesToString(self._log.get(index - 1)._requestResponse.getRequest())+"\n\n")
                        # print("\n".join(analyze)+"\n\n\n\n\n")
                        # print("\n\n====Response====\n\n{}\n\n==========\n\n".format("\n".join(self._headers)))
                        # print("\n\n====Response====\n\n{}\n\n==========\n\n".format(self._helpers.bytesToString(msg)))
                        break



        '''
        msg = ''
        if messageIsRequest: 
            msg = messageInfo.getRequest()
            analyze = self._helpers.analyzeRequest(msg)
            self._headers = list(analyze.getHeaders())

            for headers in self._headers:
                if headers.lower().startswith("accept:"):
                    accept = headers.split(":")[1].lower()
                    check = False
                    for accepts in request_filter_Accpet:
                        if accept.find(accepts) != -1:
                            for accepts in filter_ContentType:
                                if accept.find(accepts) != -1:
                                    print("\n\n====Request====\n\n{}\n\n==========\n\n".format("\n".join(self._headers)))
                                    # print("\n\n====Request====\n\n{}\n\n==========\n\n".format(self._helpers.bytesToString(msg)))
                                    break
                            else: break
                    else:
                        print("\n\n====Request====\n\n{}\n\n==========\n\n".format("\n".join(self._headers)))
                        # print("\n\n====Request====\n\n{}\n\n==========\n\n".format(self._helpers.bytesToString(msg)))


        else: 
            msg = messageInfo.getResponse()
            analyze = self._helpers.analyzeResponse(msg)
            self._headers = list(analyze.getHeaders())
            
            body = messageInfo.getResponse()[analyze.getBodyOffset():]


            for headers in self._headers:
                if headers.lower().startswith("content-type:"):
                    content_type = headers.split(":")[1].lower()
                    for ContentTypes in filter_ContentType:
                        if content_type.find(ContentTypes) != -1:
                            try:
                                print("\n\n====Response====\n\n{}\n\n==========\n\n".format("\n".join(self._headers)))
                                # print("\n\n====Response====\n\n{}\n\n==========\n\n".format(self._helpers.bytesToString(msg)))
                                break
                            except:
                                print("exception")
        '''
class LogEntry:
    def __init__(self, tool, requestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url

FixBurpExceptions()