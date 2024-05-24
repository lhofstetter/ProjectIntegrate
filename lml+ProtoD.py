'''
#
LML Protocol:
{
    type: pairing | signal_data | candidate | configure | calibration,
    noise: noise_level_in_dB, (this will hopefully, at least in the future, allow us to assign a weight to each distance calc on how much we can rely on it, this
    also allows us to change protocol if the channel is noisy)
    IF type = signal_data
    devices: {
        name_of_device: distance_from_device
    }
    ELSE IF type = candidate
    device: device_name,
    action: add | remove,
    ELSE IF type = configure
    action: disconnect | change_port | change_protocol,
    port: number_of_port (if action = change_port or change_protocol),
    protocol: 0 | 1 (0 = UDP, 1 = TCP. Port num must also be included. Only used if action = change_protocol)
    ELSE IF type = calibration
    num_of_calibration_packets: int (number of packets for leaves to send in order to see each other),
    leaf: MAC_ADDR_OF_LEAF_TO_TRANSMIT (any leaf that this isn't their mac address automatically goes into listen mode),
    ELSE
    socket_to_communicate: socket_number, (only sent if from parent to child)
    type_of_socket_used_for_communication: 0 | 1, (0 = UDP, 1 = TCP, allows for flexible transport layer configuration)
    interval: x ms, (interval rate that the node should send data to parent, only sent from parent to child)

}
'''


import math

"""
The reason for this file is that my brain ain't braining hard enough to implement this from the ground up in C++.
So, I'm prototyping it in Python first. 

"""

measured_power = {
    "raspi": -90, # just a dummy measurement, not actual value
    "iphone": -49, # actual measurement at 1 meter from my iPhone 12 Pro Max so DON'T CHANGE IT
}

N = 3

def distance(node_name, node_instant_rssi):
    global N

    return math.pow(10, (measured_power[node_name] - node_instant_rssi)/(10*N))

def location(node_name, rssi_from_parent, rssi_from_nodes):
    distances = [distance(node_name, rssi_from_parent)]

    for rssi in rssi_from_nodes:
        distances.append(distance(node_name, rssi))
    
    pass

def find_most_seperated_nodes(nodes: dict):
    
    pass


def create_map(nodes: dict): # dict of form {"node_label": current_rssi}
    farthest_node, next_farthest_node = ([], [])

    for node in nodes.keys():
        if len(farthest_node) == 0:
            farthest_node.extend([node, distance(node, nodes[node])])
        elif len(next_farthest_node) == 0:
            next_farthest_node.extend([node, distance(node, nodes[node])])
        else:
            if distance(node, nodes[node]) > farthest_node[1]:
                farthest_node[0] = node
                farthest_node[1] = distance(node, nodes[node])
            elif distance(node, node[node]) > next_farthest_node[1]:
                next_farthest_node[0] = node
                next_farthest_node[1] = distance(node, nodes[node])

    # farthest_node and next_farthest_node are the two nodes which will be used for our triangle that helps us begin to form our map.
    # remember, the farthest points are the edge of the map. 




    pass


