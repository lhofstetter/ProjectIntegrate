/*
    LML Protocol:
    {
        type: pairing | signal_data | candidate | configure,
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
        ELSE
        socket_to_communicate: socket_number, (only sent if from parent to child)
        type_of_socket_used_for_communication: 0 | 1, (0 = UDP, 1 = TCP, allows for flexible transport layer configuration)
        interval: x ms, (interval rate that the node should send data to parent, only sent from parent to child)
    }

*/