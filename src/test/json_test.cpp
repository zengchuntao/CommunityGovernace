#include "Common/nlohmann/json.hpp"

#include <iostream>
#include <fstream>

#include <string>

using namespace std;
using namespace nlohmann;
int main(int argc, char*  argv[]) {
    
    if ( argc < 2 ) {
        std::cout << "usage: " << argv[0] << " json_file_path" << std::endl;
        exit(-1);
    }

    auto* loc = std::localeconv();
    
    std::cout <<"decimal sybol: " << loc->decimal_point << "\n";
    cout << "thousands_sep: " << loc->thousands_sep << "\n";

    ifstream js_file(argv[1], fstream::in);
    string strt;
    js_file >> strt;
    js_file.close();

    json obj = json::parse(strt);
    
    std::cout << "string len is " << strt.length() << std::endl;
    int ave = 0;
    int count = 0;

    for ( auto it = obj.begin(); it != obj.end(); it++ ) {
        //std::cout << it.key() << " : " << it.value() << std::endl;
        //ave += it.value().get<int>();
        count++;
    }
    ave=count?ave/count:0;
    std::cout << "ave value is " << ave << std::endl;

    auto j2 = R"({"ls":100, "pi":3.5, "ren":"good"})"_json;
    std::cout << j2 << std::endl;
    return 0;
}