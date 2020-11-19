/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * Copyright 2018-2020, paldier <paldier@hotmail.com>.
 * All Rights Reserved.
 * 
 */

#include <stdlib.h>
#include <string.h>
#include <bwdpi.h>
#include <httpd.h>
#include <json.h>

int get_lang_num_merlinr()
{
	return 9999;
}

int check_lang_support_merlinr(char *lang)
{
	if(strstr("BR CN CZ DE EN ES FR HU IT JP KR MS NL PL RU RO SL TH TR TW UK", lang))
		return 1;
	return 0;
}

#if defined(R7000P)
extern int is_rp_express_2g();
extern int is_rp_express_5g();
extern int is_concurrep();
extern int is_aicloudipk();
extern int RCisSupport(char *name);
extern int is_hnd();
extern int is_localap();
extern int usbPortMax();
extern int is_usbX();
extern int is_usb3();
extern int is_wl_mfp();
extern int is_wlopmode();
extern int is_11AC();
extern int is_yadns();
extern int is_noRouter();
extern int is_RPMesh();
extern int is_odm();
extern int totalband();
extern int separate_ssid(char *model);
extern int mssid_count();
extern int dump_dpi_support(int index);

int is_uu_accel_merlinr()
{
	char *productid, *tcode, *odmpid;
	int result;
	productid = nvram_safe_get("productid");
	odmpid = get_productid();
	tcode = nvram_safe_get("territory_code");
	if(!nvram_get("uu_enable") || nvram_get_int("uu_enable")== 0)
		return 0;
#if defined(R7000P) || defined(K3) || defined(SBRAC1900P) || defined(SBRAC3200P)
	return 1;
#else
	if (strncmp(tcode, "CN", 2))
		return 0;
#endif
	result = nvram_get_int("ntp_ready");
	if (result)
	{
		if (nvram_get("sw_mode") && nvram_get_int("sw_mode") != 1)
			result = 0;
		else
		{
			
			if ((!strcmp(productid, "RT-AC68U") || !strcmp(productid, "RT-AC82U"))
			&& strcmp(odmpid, "RT-AC68U") && strcmp(odmpid, "RT-AC1900P") && strcmp(odmpid, "RT-AC66U_B1"))
			{
				if (strcmp(odmpid, "RT-AC1750_B1"))
					result = strcmp(odmpid, "RT-AC2200") == 0;
				else
					result = 1;
			}
			else
				result = 1;
		}
	}
	return result;
}


int DPIisSupport_merlinr(const char *name)
{
#if !defined(R7000P)
	if (!strcmp(name, "dpi_mals"))
		return dump_dpi_support(INDEX_MALS);
	if (!strcmp(name, "dpi_vp"))
		return dump_dpi_support(INDEX_VP);
	if (!strcmp(name, "dpi_cc"))
		return dump_dpi_support(INDEX_CC);
	if (!strcmp(name, "adaptive_qos"))
		return dump_dpi_support(INDEX_ADAPTIVE_QOS);
#endif
	if (!strcmp(name, "traffic_analyzer"))
		return dump_dpi_support(INDEX_TRAFFIC_ANALYZER);
	if (!strcmp(name, "webs_filter"))
		return dump_dpi_support(INDEX_WEBS_FILTER);
	if (!strcmp(name, "apps_filter"))
		return dump_dpi_support(INDEX_APPS_FILTER);
	if (!strcmp(name, "web_history"))
		return dump_dpi_support(INDEX_WEB_HISTORY);
	if (!strcmp(name, "bandwidth_monitor"))
		return dump_dpi_support(INDEX_BANDWIDTH_MONITOR);
	return 0;
}

int ej_get_ui_support_merlinr(int eid, webs_t wp, int argc, char **argv)
{
	char buffer[4096];
	char *tmp;
	char *list[] = {"dpi_mals", "dpi_vp", "dpi_cc", "adaptive_qos", "traffic_analyzer", "webs_filter", "apps_filter", "web_history", "bandwidth_monitor"};
	int i, amasmode, amasRouter, cfgsync;
	struct json_object *ax = NULL;
	struct json_object *uisupport = NULL;
	memset(buffer, 0, 4096);
	uisupport = json_object_new_object();
	snprintf(buffer, sizeof(buffer), nvram_safe_get("rc_support"));
	tmp = strtok(buffer, " ");
	while (tmp)
	{
		json_object_object_add(uisupport, tmp, json_object_new_int(RCisSupport(tmp)));
		tmp = strtok(NULL, " ");
	}
	for(i = 0; i < 9; i++)
	{
		tmp = list[i];
		json_object_object_add(uisupport, tmp, json_object_new_int(DPIisSupport_merlinr(tmp)));
	}
	json_object_object_add(uisupport, "aicloudipk", json_object_new_int(is_aicloudipk()));
	json_object_object_add(uisupport, "concurrep", json_object_new_int(is_concurrep()));
	json_object_object_add(uisupport, "rp_express_2g", json_object_new_int(is_rp_express_2g()));
	json_object_object_add(uisupport, "rp_express_5g", json_object_new_int(is_rp_express_5g()));
	json_object_object_add(uisupport, "hnd", json_object_new_int(is_hnd()));
	json_object_object_add(uisupport, "localap", json_object_new_int(is_localap()));
	json_object_object_add(uisupport, "nwtool", json_object_new_int(1));
	json_object_object_add(uisupport, "usbPortMax", json_object_new_int(usbPortMax()));
	json_object_object_add(uisupport, "usbX", json_object_new_int(is_usbX()));
	json_object_object_add(uisupport, "usb3", json_object_new_int(is_usb3()));
	json_object_object_add(uisupport, "wl_mfp", json_object_new_int(is_wl_mfp()));
	json_object_object_add(uisupport, "wlopmode", json_object_new_int(is_wlopmode()));
	json_object_object_add(uisupport, "11AC", json_object_new_int(is_11AC()));
	json_object_object_add(uisupport, "yadns", json_object_new_int(is_yadns()));
	json_object_object_add(uisupport, "noRouter", json_object_new_int(is_noRouter()));
	json_object_object_add(uisupport, "RPMesh", json_object_new_int(is_RPMesh()));
	json_object_object_add(uisupport, "eula", json_object_new_int(1));
	json_object_object_add(uisupport, "odm", json_object_new_int(is_odm()));
	json_object_object_add(uisupport, "dualband", json_object_new_int(totalband() == 2));
	json_object_object_add(uisupport, "triband", json_object_new_int(totalband() == 3));
	json_object_object_add(uisupport, "separate_ssid", json_object_new_int(separate_ssid(get_productid())));
	json_object_object_add(uisupport, "mssid_count", json_object_new_int(mssid_count()));
	json_object_object_add(uisupport, "dhcp_static_dns", json_object_new_int(1));
	json_object_object_add(uisupport, "acs_dfs", json_object_new_int((strtol(nvram_safe_get("wl1_band5grp"), &tmp, 16) & 6) == 6));
#if defined(RTAC88U) || defined(RTAC3100) || defined(RTAC5300)
	json_object_object_add(uisupport, "sdk7114", json_object_new_int(1));
#elif defined(RTAC3200)
	json_object_object_add(uisupport, "sdk7", json_object_new_int(1));
#endif
	json_object_object_add(uisupport, "wanMax", json_object_new_int(2));
	json_object_object_add(uisupport, "open_nat", json_object_new_int(1));
	json_object_object_add(uisupport, "uu_accel", json_object_new_int(is_uu_accel_merlinr()));
#if !defined(RTAC68U)
	json_object_object_add(uisupport, "internetctrl", json_object_new_int(1));
#endif
	json_object_object_add(uisupport, "del_client_data", json_object_new_int(1));
	json_object_object_add(uisupport, "captcha", json_object_new_int(1));
	if (nvram_contains_word("rc_support", "amas"))
	{
		amasmode = getAmasSupportMode();
		amasRouter = amasmode == 1;
		if (amasmode != 1)
			amasRouter = amasmode == 3;
		if (amasRouter)
			json_object_object_add(uisupport, "amasRouter", json_object_new_int(1));
		if ((amasmode - 2) > 1)
		{
			if ( !amasmode )
			{
				json_object_object_add(uisupport, "amas", json_object_new_int(0));
				goto noamas;
			}
		}
		else
			json_object_object_add(uisupport, "amasNode", json_object_new_int(1));
		json_object_object_add(uisupport, "amas", json_object_new_int(1));
		if (nvram_match("sw_mode", "1") || (nvram_match("sw_mode", "3") && !nvram_get_int("wlc_psta")))
			cfgsync = 1;
		else
noamas:
			cfgsync = 0;
		json_object_object_add(uisupport, "cfg_sync", json_object_new_int(cfgsync));
	}
	if (json_object_object_get_ex(uisupport, "11AX", &ax))
	{
		json_object_object_add(uisupport, "qis_hide_he_features", json_object_new_int(strcmp(get_productid(), "RT-AX92U") == 0));
	}
	websWrite(wp, "%s\n", json_object_to_json_string(uisupport));
	json_object_put(uisupport);
	return 0;
}
#endif
