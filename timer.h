#pragma once
#include<chrono>
#include<vector>
#include<string>
enum TimeUint {
	Seconds,
	Microseconds,
	Milliseconds,
	Nanoseconds,
};

class timer
{
public:
	std::chrono::system_clock::time_point start;
	std::chrono::system_clock::time_point end;
	std::chrono::nanoseconds time_cost = std::chrono::nanoseconds(0);
	std::vector<std::chrono::nanoseconds> cost_list = {};
	std::string timer_name="";
	unsigned long long int sum_time=0;
	timer(std::string name){
		timer_name = name;
	}
	void set_start();
	void set_end();
	void compute_duration();
	void print_time_cost();
	void cal_average_duration(TimeUint uint);
	void cal_sum_time(TimeUint uint);
	void clear();
};

