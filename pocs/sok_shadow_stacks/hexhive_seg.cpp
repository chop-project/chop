// compile with: g++ -fomit-frame-pointer -fcf-protection=full -mshstk shadowstacks.cpp

#include <iostream>

#if !(__CET__ & 2)
#warning compiled without -fcf-protection=return
#endif

#if !(__CET__ & 1)
#warning compiled without -fcf-protection=branch
#endif

#ifndef __SHSTK__
#warning compiled without shadow stack
#endif

using namespace std;
int main();

void catcher();

void vuln() {
	void* data[1];
	data[2] = (char*) catcher + ((size_t) 67);
	throw 1337;
}

void catcher() {
	try {
		throw 1;
	}
	catch (...) {
		cout << "win" << endl;
		exit(0);
	}
}


int main() {
	try {
		vuln();
	}
	catch (...) {
		cout << "catch" << endl;
	}
}
