#include <stdio.h>
#include <vector>

using namespace std;

/**
 * Assumes RSSI data is passed in via the rssis vector in order of nodes. Meaning 0 is rssi measurement from parent node, 1 is node 1, 2 is node 2, etc...
 * @
*/
float * getLocation(vector<float> rssis, vector<Node> nodes) {
    int amount_of_nodes = rssis.size();

    
}