#include <stdio.h>
#include "SM9_sv.h"
#include<time.h>

int main(void)
{

	
	clock_t startTime, finishTime;//计算运行时间用
	startTime = clock();
	//for (int i = 0; i < 20; i++)
	{
		int error_code;
		error_code = SM9_SelfCheck(); 
		if (error_code)
		{
			printf("\nSM9 sign and verify self test falied!.\n");
			printf("\nError code: 0x%x\n", error_code);
			return error_code;
		}
		else
		{
			printf("\nSM9 sign and verify self test succeeded.\n");
			
		}

	}
	finishTime = clock();
	printf("StartTime         :  %f s\n", (double)startTime / CLOCKS_PER_SEC);
	printf("EndTime          :  ", (double)finishTime / CLOCKS_PER_SEC);
	printf("20 times_total :  used %f seconds\n", (double)difftime(finishTime, startTime) / CLOCKS_PER_SEC);
	printf("Average         ：%f seconds \n", (double)difftime(finishTime, startTime) / CLOCKS_PER_SEC / 20);
	return 0;
}