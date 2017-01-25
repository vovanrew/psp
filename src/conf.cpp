#include <iostream>
#include "conf.h"

//constructors
Conf::Conf() : cnfg_file("/usr/share/Config.xml"), temp_mode(0) {}

Conf::Conf(string& filename, string& iface, int& mode) : cnfg_file(filename), temp_iface(iface), temp_mode(mode) {}

//function creates and writes config data into xml doc 
int Conf::create(){
	TiXmlDocument doc;
	TiXmlDeclaration* decl = new TiXmlDeclaration( "1.0", "", "" );
	TiXmlElement * root = new TiXmlElement( "config" );
	root->SetAttribute("iface", temp_iface.c_str());
	root->SetAttribute("mode", to_string(temp_mode).c_str());
	doc.LinkEndChild( decl );
	doc.LinkEndChild( root );
	doc.SaveFile( cnfg_file.c_str() );
	
	return 0;
}

//function gets config data from xml
int Conf::get_temp(){
	if(exists() == false)
		return 1;
	TiXmlDocument *xml_file = new TiXmlDocument(cnfg_file.c_str());
	if(!xml_file->LoadFile())
    		return 1; 
    		
    	TiXmlElement *xml_level = 0;
	xml_level = xml_file->FirstChildElement("config");
	temp_iface = string(xml_level->Attribute("iface")); 
	temp_mode = stoi(string(xml_level->Attribute("mode")));
	
	return 0;
}

//check if file exists
bool Conf::exists() {
    		ifstream f(cnfg_file.c_str());
    		return f.good();
}

//working with members
string Conf::cnfg_iface() {
	return temp_iface;
}

int Conf::cnfg_mode() {
	return temp_mode;
}

void Conf::set_temp_iface(string iface) {
	temp_iface=iface;
}

void Conf::set_temp_mode(int mode) {
	temp_mode = mode;
}
