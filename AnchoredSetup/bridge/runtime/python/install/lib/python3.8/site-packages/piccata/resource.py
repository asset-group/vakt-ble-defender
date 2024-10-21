"""
Copyright (c) 2012 Maciej Wasilak <http://sixpinetrees.blogspot.com/>
              2017 Nordic Semiconductor ASA

Implementation of the lowest-level Resource class.
"""

from piccata import message
from piccata.constants import *
from itertools import chain
from piccata.types import NoResource, UnallowedMethod, UnsupportedMethod

class CoapResource(object):
    """CoAP-accessible resource."""

    server = None

    def __init__(self):
        """Initialize.
        """
        self.children = {}
        self.params = {}
        self.visible = False
        self.observers = {} # (address, token) -> observation

    observable = False
    observe_index = 0
    is_leaf = False

    def get_child(self, path):
        """Retrieve a child resource from me.

        If no resource is found, NoResource exception is raised.
        """
        if path in self.children:
            return self.children[path]
        raise NoResource

    def put_child(self, path, child):
        """Register a static child.

        You almost certainly don't want '/' in your path. If you intended to have the root of a folder,
        e.g. /foo/, you want path to be ''.
        """
        self.children[path] = child
        child.server = self.server

    def render(self, request):
        """Render a given resource. Calls a handler for respective request code in format render_CODE.

        The render method shall accept one argument with a request message. An example render method:
            rended_GET(request)

        Args:
            request (piccata.message.Message) A request for handling.
        """
        if request.code not in requests:
            raise UnsupportedMethod()
        m = getattr(self, 'render_' + requests[request.code], None)
        if not m:
            raise UnallowedMethod()
        return m(request)

    def add_param(self, param):
        self.params.setdefault(param.name, []).append(param)

    def delete_param(self, name):
        if name in self.params:
            self.params.pop(name)

    def get_param(self, name):
        return self.params.get(name)

    def encode_params(self):
        data = [""]
        param_list = chain.from_iterable(sorted(self.params.values(), key=lambda x: x[0].name))
        for param in param_list:
            data.append(param.encode())
        return (';'.join(data))

    def generate_resource_list(self, data, path=""):
        params = self.encode_params() + (";obs" if self.observable else "")
        if self.visible is True:
            if path is "":
                data.append('</>' + params)
            else:
                data.append('<' + path + '>' + params)
        for key in self.children:
            self.children[key].generate_resource_list(data, path + "/" + key)


class LinkParam(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def decode(self, rawdata):
        pass

    def encode(self):
        return '%s="%s"' % (self.name, self.value)


class CoapEndpoint(object):

    def __init__(self, root_resource):
        """Initialize CoAP endpoint.

        Args:
            root_resource (piccata.resource.CoapResource) Root resource of the resource tree.
        """
        self.root = root_resource

    def get_resource_for(self, request):
        """Get a resource for a request.

        This iterates through the resource hierarchy, calling get_child on each resource
        it finds for a path element, stopping when it hits an element where is_leaf is true.

        Args:
            request (piccata.message.Message) A request containing the Uri path to search for.
        """
        resource = self.root
        postpath = request.opt.uri_path

        while postpath and not resource.is_leaf:
            pathElement = postpath.pop(0)
            resource = resource.get_child(pathElement)
        return resource


class ResourceManager(object):

    def __init__(self, endpoint):
        """Initialize the resource manager.

        Args:
            endpoint (piccata.resource.coapEndpoint): An endpoint containing the resource tree.
        """
        self.endpoint = endpoint

    def receive_request(self, request):
        """Function for handling requests.

        This function will be called by the CoAP object after registration of ResourceManager object.

        Args:
            request (piccata.message.Message): Request received.

        Returns:
            A response to send back. None if no response shall be sent.
        """
        response = None

        try:
            resource = self.endpoint.get_resource_for(request)
            response = resource.render(request)
        except NoResource:
            response = message.Message.AckMessage(request, code=NOT_FOUND, payload=b"Error: Resource not found!")
        except UnallowedMethod:
            response = message.Message.AckMessage(request, code=METHOD_NOT_ALLOWED, payload=b"Error: Method not allowed!")
        except UnsupportedMethod:
            response = message.Message.AckMessage(request, code=METHOD_NOT_ALLOWED, payload=b"Error: Method not recognized!")

        return response
