/*
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
        leaf: IPv6 address of leaf to communicate (any leaf that doesn't have this address automatically goes into listen mode),
        ELSE
        port_to_communicate: port_number, (only sent if from parent to child)
        type_of_socket_used_for_communication: 0 | 1, (0 = UDP, 1 = TCP, allows for flexible transport layer configuration)
        interval: x ms, (interval rate that the node should send data to parent, only sent from parent to child)
        confirmation: true (only sent from child to parent after receiving connection details)
    }

*/