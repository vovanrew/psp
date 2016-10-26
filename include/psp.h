#include <iostream>
#include <tins/tins.h>
#include <map>
#include <typeinfo>
#include "conf.h"
extern "C" {
  #include "sqlite3.h"
}

using namespace Tins;
using namespace std;

//main class to sniff packets and writing records
class MySniffer{
	PDU *some_pdu;
	IP ip;
	string interface;
	sqlite3 *db;
	map <string , unsigned int> statistic;
	bool stop;
	Conf* config_fl = new Conf;
public:
	Conf* get_config();	
	
	MySniffer();
	
	MySniffer(string iface, bool stp);
	
	~MySniffer();
	
	string getIface();
	
	string usage_inf();
	
	void setIface(string iface);
		
	bool isIfaceDeff();
	
	void pkgMonitor(bool stp);
	
	void put_update_data();
	
	int select_data(const string& ip);
	
	void set_cmd(bool stp);
	
	bool get_cmd();
	
	void config();
};
