#include "rc.h"
#if defined(K3)
#include "k3.h"
#elif defined(R7900P) || defined(R8000P)
#include "r7900p.h"
#elif defined(R7000P)
#include "r7000p.h"
#elif defined(R8500)
#include "r8500.h"
#elif defined(SBRAC1900P)
#include "ac1900p.h"
#elif defined(SBRAC3200P)
#include "ac3200p.h"
#elif defined(F9K1118)
#include "f9k1118.h"
#elif defined(TY6201_BCM) || defined(TY6201_RTK)
#include "ty6201.h"
#else
#include "merlinr.h"
#endif

void start_uu(void)
{
	stop_uu();

	if(getpid()!=1) {
		notify_rc("start_uu");
		return;
	}

	if(nvram_get_int("uu_enable"))
#if defined(R8000P) || defined(RTAC3200) || defined(RTAC3100) || defined(EA6700) || defined(RAX20) || defined(SBRAC1900P) || defined(R7000P) || defined(RMAC2100) || defined(TY6201_BCM) || defined(TY6201_RTK)
		exec_uu_merlinr();
#else
		exec_uu();
#endif
}


void stop_uu(void)
{
	doSystem("killall uuplugin_monitor.sh");
	if (pidof("uuplugin") > 0)
		doSystem("killall uuplugin");
}
