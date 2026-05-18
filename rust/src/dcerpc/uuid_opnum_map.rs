/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

// Author: Shivani Bhardwaj <shivani@oisf.net>

//! This module contains the map of DCERPC UUID to service name as well as
//! DCERPC UUID + opnum to the procedure name.

pub fn get_uuid_service_name(uuid: String) -> Option<&'static str> {
    match uuid.as_str() {
        "367abb81-9844-35f1-ad32-98f038001003" => Some("svcctl"),
        "86d35949-83c9-4044-b424-db363231fd0c" => Some("ITaskSchedulerService"),
        "378e52b0-c0a9-11cf-822d-00aa0051e40f" => Some("sasec"),
        "1ff70682-0a51-30e8-076d-740be8cee98b" => Some("atsvc"),
        "0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53" => Some("idletask"),
        "906b0ce0-c70b-1067-b317-00dd010662da" => Some("IXnRemote"),
        "ae33069b-a2a8-46ee-a235-ddfd339be281" => Some("IRPCRemoteObject"),
        "0b6edbfa-4a24-4fc6-8a23-942b1eca65d1" => Some("IRPCAsyncNotify"),
        "afa8bd80-7d8a-11c9-bef4-08002b102989" => Some("mgmt"),
        "f5cc59b4-4264-101a-8c59-08002b2f8426" => Some("FrsRpc"),
        "000001a0-0000-0000-c000-000000000046" => Some("IRemoteSCMActivator"),
        "00000143-0000-0000-c000-000000000046" => Some("IRemUnknown2"),
        "12345778-1234-abcd-ef00-0123456789ab" => Some("lsarpc"),
        "76f03f96-cdfd-44fc-a22c-64950a001209" => Some("IRemoteWinspool"),
        "12345678-1234-abcd-ef00-01234567cffb" => Some("netlogon"),
        "e3514235-4b06-11d1-ab04-00c04fc2dcd2" => Some("drsuapi"),
        "5261574a-4572-206e-b268-6b199213b4e4" => Some("AsyncEMSMDB"),
        "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57" => Some("IActivation"),
        "99fcfec4-5260-101b-bbcb-00aa0021347a" => Some("IObjectExporter"),
        "e1af8308-5d1f-11c9-91a4-08002b14a0fa" => Some("epmapper"),
        "12345778-1234-abcd-ef00-0123456789ac" => Some("samr"),
        "4b324fc8-1670-01d3-1278-5a47bf6ee188" => Some("srvsvc"),
        "45f52c28-7f9f-101a-b52b-08002b2efabe" => Some("winspipe"),
        "6bffd098-a112-3610-9833-46c3f87e345a" => Some("wkssvc"),
        "3919286a-b10c-11d0-9ba8-00c04fd92ef5" => Some("dssetup"),
        "12345678-1234-abcd-ef00-0123456789ab" => Some("spoolss"),
        "1544f5e0-613c-11d1-93df-00c04fd7bd09" => Some("exchange_rfr"),
        "f5cc5a18-4264-101a-8c59-08002b2f8426" => Some("nspi"),
        "a4f1db00-ca47-1067-b31f-00dd010662da" => Some("exchange_mapi"),
        "9556dc99-828c-11cf-a37e-00aa003240c7" => Some("IWbemServices"),
        "f309ad18-d86a-11d0-a075-00c04fb68820" => Some("IWbemLevel1Login"),
        "d4781cd6-e5d3-44df-ad94-930efe48a887" => Some("IWbemLoginClientID"),
        "44aca674-e8fc-11d0-a07c-00c04fb68820" => Some("IWbemContext interface"),
        "674b6698-ee92-11d0-ad71-00c04fd8fdff" => Some("IWbemContext unmarshaler"),
        "dc12a681-737f-11cf-884d-00aa004b2e24" => Some("IWbemClassObject interface"),
        "4590f812-1d3a-11d0-891f-00aa004b2e24" => Some("IWbemClassObject unmarshaler"),
        "9a653086-174f-11d2-b5f9-00104b703efd" => Some("IWbemClassObject interface"),
        "c49e32c6-bc8b-11d2-85d4-00105a1f8304" => Some("IWbemBackupRestoreEx interface"),
        "7c857801-7381-11cf-884d-00aa004b2e24" => Some("IWbemObjectSink interface"),
        "027947e1-d731-11ce-a357-000000000001" => Some("IEnumWbemClassObject interface"),
        "44aca675-e8fc-11d0-a07c-00c04fb68820" => Some("IWbemCallResult interface"),
        "c49e32c7-bc8b-11d2-85d4-00105a1f8304" => Some("IWbemBackupRestore interface"),
        "a359dec5-e813-4834-8a2a-ba7f1d777d76" => Some("IWbemBackupRestoreEx interface"),
        "f1e9c5b2-f59b-11d2-b362-00105a1f8177" => Some("IWbemRemoteRefresher interface"),
        "2c9273e0-1dc3-11d3-b364-00105a1f8177" => Some("IWbemRefreshingServices interface"),
        "423ec01e-2e35-11d2-b604-00104b703efd" => Some("IWbemWCOSmartEnum interface"),
        "1c1c45ee-4395-11d2-b60b-00104b703efd" => Some("IWbemFetchSmartEnum interface"),
        "541679AB-2E5F-11d3-B34E-00104BCC4B4A" => Some("IWbemLoginHelper interface"),
        "51c82175-844e-4750-b0d8-ec255555bc06" => Some("KMS"),
        "50abc2a4-574d-40b3-9d66-ee4fd5fba076" => Some("dnsserver"),
        "3faf4738-3a21-4307-b46c-fdda9bb8c0d5" => Some("AudioSrv"),
        "c386ca3e-9061-4a72-821e-498d83be188f" => Some("AudioRpc"),
        "6bffd098-a112-3610-9833-012892020162" => Some("browser"),
        "91ae6020-9e3c-11cf-8d7c-00aa00c091be" => Some("ICertPassage"),
        "c8cb7687-e6d3-11d2-a958-00c04f682e16" => Some("DAV RPC SERVICE"),
        "82273fdc-e32a-18c3-3f78-827929dc23ea" => Some("eventlog"),
        "3d267954-eeb7-11d1-b94e-00c04fa3080d" => Some("HydraLsPipe"),
        "894de0c0-0d55-11d3-a322-00c04fa321a1" => Some("InitShutdown"),
        "d95afe70-a6d5-4259-822e-2c84da1ddb0d" => Some("WindowsShutdown"),
        "8d0ffe72-d252-11d0-bf8f-00c04fd9126b" => Some("IKeySvc"),
        "68b58241-c259-4f03-a2e5-a2651dcbc930" => Some("IKeySvc2"),
        "0d72a7d4-6148-11d1-b4aa-00c04fb66ea0" => Some("ICertProtect"),
        "f50aac00-c7f3-428e-a022-a6b71bfb9d43" => Some("ICatDBSvc"),
        "338cd001-2244-31f1-aaaa-900038001003" => Some("winreg"),
        "3dde7c30-165d-11d1-ab8f-00805f14db40" => Some("BackupKey"),
        "3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5" => Some("RpcSrvDHCPC"),
        "3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6" => Some("dhcpcsvc6"),
        "2f59a331-bf7d-48cb-9ec5-7c090d76e8b8" => Some("lcrpc"),
        "5ca4a760-ebb1-11cf-8611-00a0245420ed" => Some("winstation_rpc"),
        "12b81e99-f207-4a4c-85d3-77b42f76fd14" => Some("ISeclogon"),
        "d6d70ef0-0e3b-11cb-acc3-08002b1d29c3" => Some("NsiS"),
        "d3fbb514-0e3b-11cb-8fad-08002b1d29c3" => Some("NsiC"),
        "d6d70ef0-0e3b-11cb-acc3-08002b1d29c4" => Some("NsiM"),
        "17fdd703-1827-4e34-79d4-24a55c53bb37" => Some("msgsvc"),
        "5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc" => Some("msgsvcsend"),
        "8d9f4e40-a03d-11ce-8f69-08003e30051b" => Some("pnp"),
        "57674cd0-5200-11ce-a897-08002b2e9c6d" => Some("lls_license"),
        "342cfd40-3c6c-11ce-a893-08002b2e9c6d" => Some("llsrpc"),
        "4fc742e0-4a10-11cf-8273-00aa004ae673" => Some("netdfs"),
        "83da7c00-e84f-11d2-9807-00c04f8ec850" => Some("sfcapi"),
        "2f5f3220-c126-1076-b549-074d078619da" => Some("nddeapi"),
        _ => None,
    }
}
