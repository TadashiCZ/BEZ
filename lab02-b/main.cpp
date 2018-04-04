#include <iostream>
#include <openssl/evp.h>
#include <vector>
#include <sstream>
#include <string>
#include <cstring>
#include "stdint.h"

using namespace std;

int main(void) {
	string known_ot;
	vector<uint8_t> known_ct;
	vector<uint8_t> unknown_ct;
	vector<uint8_t> second_xor;

	string input1;
	string input2;

	cout << "Please, input known open text" << endl;
	cin >> known_ot;
	cout << "Please, input known cipher text" << endl;
	cin >> input1;
	cout << "Please, input unknown cipher text" << endl;
	cin >> input2;
	cout << known_ot << " --- " << input1 << " --- " << input2 << endl;

	for(size_t i = 0; i < input1.size(); i += 2) {
		istringstream str(input1.substr(i, 2));
		uint8_t x;
		str >> hex >> x;
		known_ct.push_back(x);
	}

	cin >> input2;
	for(size_t i = 0; i < input2.size(); i += 2) {
		istringstream str(input2.substr(i, 2));
		uint8_t x;
		str >> hex >> x;
		unknown_ct.push_back(x);
	}
	second_xor.reserve(unknown_ct.size());
	for (unsigned int i = 0; i < unknown_ct.size(); i++)
		second_xor.push_back( (uint8_t)known_ot[i] xor known_ct[i] xor unknown_ct[i]);

	for (unsigned char c : second_xor)
		cout << c;
	cout << endl;

	return 0;
}