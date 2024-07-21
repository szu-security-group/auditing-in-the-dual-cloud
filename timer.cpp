#include "timer.h"
#include<chrono>
#include<iostream>
#include <iomanip>
using namespace std;
void timer::set_start()
{
	start = std::chrono::system_clock::now();
}

void timer::set_end()
{
	end = std::chrono::system_clock::now();
	cost_list.push_back(end - start);
}

void timer::compute_duration()
{
	time_cost = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
}

void timer::print_time_cost()
{
	std::cout << (time_cost.count()) * std::chrono::nanoseconds::period::num << " ns" << std::endl;
	std::cout << (time_cost.count()) / 1000000000.0 << " ms" << std::endl;
}

void timer::cal_average_duration(TimeUint uint)
{
	unsigned long long int sum = 0;
	int j = 0;
	for (auto i = cost_list.begin(); i != cost_list.end(); i++) {
		unsigned long long int temp = std::chrono::duration_cast<std::chrono::nanoseconds>(*i).count();
		sum += temp;
		std::cout <<j<<"th " <<temp << " ";
		j++;
	}
	//std::cout<<std::endl;
	//std::cout<<sum<<" ns"<<std::endl;
	switch (uint) {
		case Seconds:
			// for (auto i = cost_list.begin(); i != cost_list.end(); i++) {
			// 	unsigned long long int temp = std::chrono::duration_cast<std::chrono::seconds>(*i).count();
			// 	sum += temp;
			// 	std::cout << temp << " ";
			// }
			// std::cout << std::endl;
			std::cout << "average duration in seconds: " << std::fixed << std::setprecision(9) << 1.0*sum / cost_list.size()/(1000*1000*1000) << std::endl;
			break;
		case Milliseconds:
			// for (auto i = cost_list.begin(); i != cost_list.end(); i++) {
			// 	unsigned long long int temp = std::chrono::duration_cast<std::chrono::milliseconds>(*i).count();
			// 	sum += temp;
			// 	std::cout << temp << " ";
			// }
			std::cout << "average duration in milliseconds: " << std::fixed << std::setprecision(6) << 1.0*sum / cost_list.size()/(1000*1000) << std::endl;
			break;

		case Microseconds:
			// for (auto i = cost_list.begin(); i != cost_list.end(); i++) {
			// 	unsigned long long int temp = std::chrono::duration_cast<std::chrono::microseconds>(*i).count();
			// 	sum += temp;
			// 	std::cout << temp << " ";
			// }
			std::cout << "average duration in microseconds: " << std::fixed << std::setprecision(3) << 1.0*sum / cost_list.size()/1000 << std::endl;
			break;
		case Nanoseconds:
			// for (auto i = cost_list.begin(); i != cost_list.end(); i++) {
			// 	unsigned long long int temp = std::chrono::duration_cast<std::chrono::nanoseconds>(*i).count();
			// 	sum += temp;
			// 	std::cout << temp << " ";
			// }
			if(cost_list.size()!=0)
				std::cout <<timer_name <<" average duration in nanoseconds: " << sum / cost_list.size() << std::endl;
			break;
	}
}

void timer::clear()
{
	sum_time = 0;
	cost_list.clear();
}

void timer::cal_sum_time(TimeUint uint){
	unsigned long long int sum = 0;
	for (auto i = cost_list.begin(); i != cost_list.end(); i++) {
		unsigned long long int temp = std::chrono::duration_cast<std::chrono::nanoseconds>(*i).count();
		sum += temp;
	}
	sum_time = sum;
	switch (uint) {
		case Seconds:
			std::cout << "sum duration in seconds: " << std::fixed << std::setprecision(9) << 1.0*sum /(1000*1000*1000) << std::endl; break;
		case Milliseconds:
			std::cout << "sum duration in milliseconds: " << std::fixed << std::setprecision(6) << 1.0*sum /(1000*1000) << std::endl; break;
		case Microseconds:
			std::cout << "sum duration in microseconds: " << std::fixed << std::setprecision(3) << 1.0*sum /1000 << std::endl; break;
		case Nanoseconds:
			std::cout << "sum duration in nanoseconds: " << sum  << std::endl; break;
	}

}

