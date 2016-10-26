#include "psp.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>

//Constructors 
MySniffer::MySniffer() : stop(false) {}

MySniffer::MySniffer(string iface, bool stp) : interface(iface), stop(stp) {}

MySniffer::~MySniffer() {
	delete some_pdu;
	delete config_fl;
}

//program options
string MySniffer::usage_inf(){
	string options = "\tOptions:\n"
			"start \t\t\tPackets are being sniffed from now on.\n"
			"stop  \t\t\tPackets are not sniffed.\n"
			"show [ip] count \tOutputs number of packets received from ip address.\n"
			"select iface [iface] \tSelect interface for sniffing.\n"
			"--help \t\t\tShow usage information.\n";
	return options;
}

//interface functions
string MySniffer::getIface() {
	return interface;
}
		
void MySniffer::setIface(string iface) {
	interface = iface;
}

bool MySniffer::isIfaceDeff() {
	if(interface.length() == 0)
		return false;
	
	return true;
}

//sniffs for packets and record to db
void MySniffer::pkgMonitor(bool stp) {
	Sniffer* sniffer;
	if (isIfaceDeff() && !stp)
		sniffer = new Sniffer(getIface());
	else {
		delete sniffer;
		exit(0);
	}
	
	map <string, unsigned int>::iterator it;
	
	while(!stp) {
		some_pdu = sniffer->next_packet();
		try {
			ip = some_pdu->rfind_pdu<IP>();
		} catch (pdu_not_found) {
			continue;
		}
		it = statistic.find(ip.src_addr().to_string());
		
		if(it != statistic.end())
			statistic.at(ip.src_addr().to_string()) += 1;
		else
			statistic.insert(pair<string, unsigned int>(ip.src_addr().to_string(), 1));
		if(statistic.size() == 2){
			put_update_data();
		}
		if(get_config()->get_temp() == 0)
			set_cmd(get_config()->cnfg_mode());
		if(get_cmd() == 1){
			delete sniffer;
			exit(0);
		}
	}

	delete sniffer;
}

//stop or start mode
void MySniffer:: set_cmd(bool stp){
	stop = stp;
}

bool MySniffer::get_cmd(){
	return stop;
}

//returns configuration class that contains interface information and running mode in xml
Conf* MySniffer :: get_config(){
	return config_fl;
}

//data base manage
int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    
    NotUsed = 0;
    
    for (int i = 0; i < argc; i++) {

        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    
    printf("\n");
    
    return 0;
}

void MySniffer::put_update_data() {
	
	if(mkdir("/usr/share/PSPDataBase",  ACCESSPERMS) == -1) {
		if(errno != EEXIST) {
		cout << "Error with directory creating" << endl;
		exit(1);
		}
	}
	
   	char *zErrMsg = 0;
   	string sql = 	"CREATE TABLE IF NOT EXISTS traffic("
         		"ip TEXT NOT NULL," 
         		"packets INT NOT NULL,"
         		"UNIQUE(ip, packets));";
   	
   	if(sqlite3_open("/usr/share/PSPDataBase/traffic.db", &db)) {
   		cout << "Can't open database: \n";
   		exit(1);
   	}
   	
   	if(sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg))
   		cout << "SQL error. \n" << endl;
   	
   	for (auto it = statistic.begin(); it != statistic.end(); it++){
   		sql =	" UPDATE traffic SET ip='" + it->first + "', packets=packets + " + to_string(it->second) + " WHERE ip='" + it->first + "';" + 
   		 	" INSERT INTO traffic (ip, packets) SELECT '" + it->first + "', " + to_string(it->second) + " WHERE (Select Changes() = 0);";
 		
         	if(sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg))
         		cout << "SQL error. \n" << endl;
         }
         
   	for (auto it = statistic.begin(); it != statistic.end(); it++)
   		statistic.erase(it);
   		
   	sqlite3_close(db);
   	delete zErrMsg;
}
 
int MySniffer::select_data(const string& ip) {
	char *zErrMsg = 0;

	string sql = "SELECT ip, packets FROM traffic WHERE ip='" + ip + "';";
	
	if(sqlite3_open("/usr/share/PSPDataBase/traffic.db", &db)) {
   		cout << "Can't open database: \n";
   		exit(1);
   	}
	
	if(sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg)){
   		return 1;
   	}
  	
   	sqlite3_close(db);
   	delete zErrMsg;
   	return 0;
}	

	
int main(int argc, char* argv[]) {

	pid_t pid, sid;
        
        pid = fork();
        if (pid < 0) {
                exit(EXIT_FAILURE);
        }
        
        if (pid > 0) {
                exit(EXIT_SUCCESS);
        }

        umask(0);
                
        sid = setsid();
        if (sid < 0) {
                exit(EXIT_FAILURE);
        }
        

        if ((chdir("/")) < 0) {
                exit(EXIT_FAILURE);
        }
  
	MySniffer snf;
        
	if(argc == 1 || argc == 3 || argc > 4) {
		cout << "Wrong options. Read program options.\n" << snf.usage_inf() << endl;
		exit(1);
	}
	
	for(int i = 1; i < argc; ++i) {
		if(strcmp(argv[i], "select") == 0) {
			for(int j = i + 1; j < argc; ++j){
				if(strcmp(argv[j], "iface") == 0){
					if(snf.get_config()->get_temp() == 0){
						snf.set_cmd(snf.get_config()->cnfg_mode());
						snf.setIface(string(argv[3]));
					
						snf.get_config()->set_temp_iface(string(argv[3]));
						snf.get_config()->set_temp_mode(snf.get_cmd());
						snf.get_config()->create();
					
						snf.pkgMonitor(snf.get_cmd());
					}
					
					if(snf.get_config()->exists() != true) {
						snf.set_cmd(snf.get_config()->cnfg_mode());
						snf.setIface(string(argv[3]));
						snf.get_config()->set_temp_iface(string(argv[3]));
						snf.get_config()->set_temp_mode(snf.get_cmd());
						snf.get_config()->create();
						exit(0);	
					}
				}
			}
			break;		
		}
		
		if(strcmp(argv[i], "show") == 0) {
			for(int j = i + 1; j < argc; ++j) {
				if(strcmp(argv[j], " count")){
					if(snf.select_data(argv[2])==1){
						cout << "There is no adress " << argv[2] << " or data base wasn't created.\n"
						<< "Check if you select network interface.\n";
					}
					if(snf.get_config()->exists() != true)
						exit(0);
					if(snf.get_config()->get_temp() == 0) {
						snf.setIface(snf.get_config()->cnfg_iface());
						snf.set_cmd(snf.get_config()->cnfg_mode());
						snf.pkgMonitor(snf.get_cmd());
					}
					else exit(0);
				}
			}
			break;
		}
		
		if(strcmp(argv[i], "--help") == 0) {
			cout << snf.usage_inf() << endl;
			if(snf.get_config()->exists() != true)
				exit(0);
			if(snf.get_config()->get_temp() == 0) {
				snf.setIface(snf.get_config()->cnfg_iface());
				snf.set_cmd(snf.get_config()->cnfg_mode());
				snf.pkgMonitor(snf.get_cmd());
			}
			else exit(0);
		}
		
		if(strcmp(argv[i], "stop") == 0) {
			if(snf.get_config()->exists() != true)
				exit(0);
			if(snf.get_config()->get_temp() == 0)
				snf.setIface(snf.get_config()->cnfg_iface());
				
			snf.get_config()->set_temp_mode(1);
			snf.get_config()->create();
			snf.set_cmd(1);
			if(snf.get_config()->get_temp() == 0) {
				snf.setIface(snf.get_config()->cnfg_iface());
				snf.set_cmd(snf.get_config()->cnfg_mode());
			}
			exit(0);
		}
		
		if(strcmp(argv[i], "start") == 0){
			if(snf.get_config()->exists() == true){
				snf.get_config()->get_temp();
				snf.get_config()->set_temp_mode(0);
				snf.setIface(snf.get_config()->cnfg_iface());
				snf.set_cmd(snf.get_config()->cnfg_mode());
				snf.get_config()->create();
				snf.pkgMonitor(snf.get_cmd());
			}
			else {
				cout << "Select your network interface. Read program options.\n" << snf.usage_inf() << endl;
				exit(0);
			}
		}
	}
	
	return 0;
}
