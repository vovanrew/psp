#include <fstream>
#include "tinyxml.h"

using namespace std;

class Conf {
	string cnfg_file;
	string temp_iface;
	int temp_mode;
	
public:
	Conf();
	Conf(string& filename, string& iface, int& mode);
	int create();
	int get_temp();
	string cnfg_iface();
	int cnfg_mode();
	void set_temp_iface(string iface);
	void set_temp_mode(int mode);
	bool exists ();
};
