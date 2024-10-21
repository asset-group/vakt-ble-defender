"""
Copyright (c) 2012 Maciej Wasilak <http://sixpinetrees.blogspot.com/>
              2017 Nordic Semiconductor ASA

CoAP block transfer helper functions.
"""

import piccata

from piccata.constants import *
from piccata.message import Message

def extract_block(data, number, size_exp):
    size = size_exp_to_size(size_exp)
    offset = number * size
    if offset < len(data):
        if offset + size < len(data):
            end = offset + size
            more = True
        else:
            end = len(data)
            more = False

        data_block = data[offset:end]

        return (data_block, more)

    return (None, None)

def size_exp_to_size(size_exp):
    return 2 ** (size_exp + 4)

def create_block_1_request(data, number, uri_path, mtype=CON, code=PUT, size_exp=DEFAULT_BLOCK_SIZE_EXP):
    """Generate a block 1 request

    Args:
        number (int): Block number to send.
        uri_path (tuple): A tuple containing strings representing target resource URI path.
        type (int): Type of the request (CON/NON).
        code (int): Code of the request (PUT/POST).

    Returns:
        piccata.message.Message: A request contating specific block 1 option and payload.
    """
    data_block, more = extract_block(data, number, size_exp)

    if data_block == None:
        raise ValueError("Block 1 request number out of bound.")

    if type not in (CON, NON):
        raise ValueError("Block 1 request should be of type CON or NON")

    if code not in (PUT, POST):
        raise ValueError("Block 1 request should be PUT or POST")

    request = Message(mtype=mtype, code=code, payload=data_block, token=piccata.message.random_token())
    request.opt.uri_path = uri_path
    request.opt.block1 = (number, more, size_exp)
    return request

def create_block_1_response(request):
    """Generate a block 1 response for a specific request.

    Args:
        request (piccata.message.Message): A request received.

    Returns:
        piccata.message.Message: A generated response.
    """
    raise NotImplemented("Feature is not yet implemented")

def create_block_2_request(number, uri_path, mtype=CON, size_exp=DEFAULT_BLOCK_SIZE_EXP):
    """Generate a block 2 request

    Args:
        uri_path (tuple): A tuple containing strings representing target resource URI path.
        number (int): Requested block number.
        type (int): Type of the request (CON/NON).

    Returns:
        piccata.message.Message: A request contating specific block 2 option.
    """
    if type not in (CON, NON):
        raise ValueError("Block 2 request should be of type CON or NON")

    request = Message(mtype=mtype, code=GET, token=piccata.message.random_token())
    request.opt.uri_path = uri_path
    request.opt.block2 = (number, False, size_exp)
    return request

def create_block_2_response(data, request):
    """Generate a block 2 response for a specific request.

    Args:
        request (piccata.message.Message): A request received.

    Returns:
        piccata.message.Message: A response generated.
    """
    data_block, more = extract_block(data, request.opt.block2.num, request.opt.block2.szx)

    if data_block == None:
        raise ValueError("Block 2 request number out of bound.")

    if request.mtype == CON:
        response = Message.AckMessage(request, code=CONTENT, payload=data_block)
    else:
        response = Message(mtype=NON, code=CONTENT, payload=data_block, token=request.token)

    response.opt.block2 = (request.opt.block2.num, more, request.opt.block2.szx)
    return response
