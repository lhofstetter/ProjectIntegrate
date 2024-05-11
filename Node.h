#include <time.h>
#include <stdio.h>

/**
 * Current: User inputs lat and lng by looking at location in Maps on phone. 
*/

class Node {
public:
    Node(float lat, float lng, bool child = false): child(child) {
       this -> lat = lat;
       this -> lng = lng;
    }
    float * getLocation() {
        static float location[2] = {this -> lng, this -> lat};
        return location;
    }
    float * getDistance(Node to) {
        
    }
    //float calculateDistance(Device d);
private:
    float lng;
    float lat;
    bool child;
};