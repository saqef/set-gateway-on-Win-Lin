//QList<QNetworkInterface> ls=QNetworkInterface::allInterfaces();
//prop[i]-address (QString) 

#ifdef Q_OS_WIN

                HRESULT hres;

                // Step 1: --------------------------------------------------
                // Initialize COM. ------------------------------------------

                CoUninitialize();
                //OleInitialize(NULL);
                hres = CoInitializeEx(0, COINIT_MULTITHREADED);
                if (FAILED(hres))
                {
                    return answer=("Failed to initialize COM library. Error code = 0x"+QString::number(hres));
                }

                // Step 2: --------------------------------------------------
                // Set general COM security levels --------------------------

                hres = CoInitializeSecurity(
                    NULL,
                    -1,                          // COM negotiates service
                    NULL,                        // Authentication services
                    NULL,                        // Reserved
                    RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
                    RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
                    NULL,                        // Authentication info
                    EOAC_NONE,                   // Additional capabilities
                    NULL                         // Reserved
                );


                if (FAILED(hres))
                {
                    CoUninitialize();
                    return answer=("Failed to initialize security. Error code = 0x"+hres);
                }

                // Step 3: ---------------------------------------------------
                // Obtain the initial locator to WMI -------------------------

                IWbemLocator *pLoc = NULL;

                hres = CoCreateInstance(CLSID_WbemLocator,0,CLSCTX_INPROC_SERVER,IID_IWbemLocator, (LPVOID *)&pLoc);

                if (FAILED(hres))
                {
                    CoUninitialize();
                    return answer=("Failed to create IWbemLocator object. Err code = 0x"+hres);
                }

                // Step 4: ---------------------------------------------------
                // Connect to WMI through the IWbemLocator::ConnectServer method

                IWbemServices *pSvc = NULL;

                // Connect to the local root\cimv2 namespace
                // and obtain pointer pSvc to make IWbemServices calls.
                hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),NULL,NULL,0,NULL,0,0,&pSvc);

                if (FAILED(hres))
                {
                    pLoc->Release();
                    CoUninitialize();
                    return answer=("Could not connect. Error code = 0x"+hres);
                }

                //answer=("Connected to ROOT\\CIMV2 WMI namespace");


                // Step 5: --------------------------------------------------
                // Set security levels for the proxy ------------------------

                hres = CoSetProxyBlanket(
                    pSvc,                        // Indicates the proxy to set
                    RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
                    RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
                    NULL,                        // Server principal name
                    RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
                    RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
                    NULL,                        // client identity
                    EOAC_NONE                    // proxy capabilities
                );

                if (FAILED(hres))
                {
                    pSvc->Release();
                    pLoc->Release();
                    CoUninitialize();
                    return answer=("Could not set proxy blanket. Error code = 0x"+hres);
                }

                // Step 6: --------------------------------------------------
                // Use the IWbemServices pointer to make requests of WMI ----

                // set up to call the Win32_Process::Create method
                BSTR MethodName = SysAllocString(L"SetGateways");
                BSTR ClassName = SysAllocString(L"Win32_NetworkAdapterConfiguration");

                IWbemClassObject* pClass = NULL;
                hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

                if (FAILED(hres))
                {
                    return answer=("pSvc->GetObject. Error code = 0x"+hres);
                }

                IWbemClassObject* pInParamsDefinition = NULL;
                hres = pClass->GetMethod(MethodName, 0, &pInParamsDefinition, NULL);

                if (FAILED(hres))
                {
                    return answer=("GetMethod. Error code = 0x"+hres);
                }

                IWbemClassObject* pClassInstance = NULL;
                hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

                if (FAILED(hres))
                {
                    return answer=("SpawnInstance. Error code = 0x"+hres);
                }


                ULONG count = 1;		//  ip\mask list lenght
                size_t outSize;


                int fIndex=0;			// interface index

                LPWSTR adapterName=QStringToLPWSTR(ls[id].humanReadableName());
                GetAdapterIndex(adapterName,(PULONG)fIndex);

                std::wstring gateWstr=prop[i].section(':', 1).toStdWString();
                wchar_t* tmp_gate=const_cast<wchar_t*>(gateWstr.c_str());

                // Convert from multibyte strings to wide character arrays
                //wchar_t tmp_ip[_countof(iptemp)];
                    SAFEARRAY *gate_list = SafeArrayCreateVector(VT_BSTR, 0, count);
                // Insert into safe arrays, allocating memory as we do so (destroying the safe array will destroy the allocated memory)
                    long idx[] = { 0 };
                    BSTR gateT = SysAllocString(tmp_gate);
                    idx[0] = 0;
                    if (FAILED(SafeArrayPutElement(gate_list, idx, gateT)))
                    {
                       return answer=( "SafeArrayPutElement ip= 0x"+hres);
                    }
                    SysFreeString(gateT);




                    // Create the values for the in parameters
                    VARIANT gate;
                    VariantInit(&gate);
                    gate.vt = VT_ARRAY | VT_BSTR;
                    gate.parray = gate_list;


                    // Store the value for the in parameters
                    hres = pClassInstance->Put(L"DefaultIPGateway", 0, &gate, 0);

                if (FAILED(hres))
                {
                   return answer=("put gate. Error code = 0x"+hres);
                }


                char indexString[10];
                _itoa_s(fIndex, indexString, 10,10);

                char instanceString[100];
                wchar_t w_instanceString[100];
                strcpy_s(instanceString, "Win32_NetworkAdapterConfiguration.Index='");
                strcat_s(instanceString, indexString);
                strcat_s(instanceString, "'");

                size_t size = 100;
                mbstowcs_s(&outSize, w_instanceString, size, instanceString, size - 1);

                BSTR InstancePath = SysAllocString(w_instanceString);



                // Execute Method
                IWbemClassObject* pOutParams = NULL;
                hres = pSvc->ExecMethod(InstancePath, MethodName, 0,NULL, pClassInstance, &pOutParams, NULL);

                if (FAILED(hres))
                {
                    VariantClear(&gate);
                    SysFreeString(ClassName);
                    SysFreeString(MethodName);
                    pClass->Release();
                    pClassInstance->Release();
                    pInParamsDefinition->Release();
                    pOutParams->Release();
                    pSvc->Release();
                    pLoc->Release();
                    CoUninitialize();
                    return answer=("Could not execute method. Error code = 0x"+hres);
                }

                // To see what the method returned,
                // use the following code.  The return value will
                // be in &varReturnValue
                VARIANT varReturnValue;
                hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varReturnValue, NULL, 0);

                // Clean up
                //--------------------------
                VariantClear(&gate);
                VariantClear(&varReturnValue);
                SysFreeString(ClassName);
                SysFreeString(MethodName);
                pClass->Release();
                pClassInstance->Release();
                pInParamsDefinition->Release();
                pOutParams->Release();
                pLoc->Release();
                pSvc->Release();
                CoUninitialize();
                answer=("Ok");


               /* QStringList ipGateway;
                QString temp=prop[i].section(':', 1);
                ipGateway=temp.split(".");
                temp="0x";
                if (ipGateway.length()!=4)
                    return "Gateway address is uncorrect";
                else
                {
                    for (int j=0;j<4;++j)
                    {
                        temp+=QString::number( ipGateway[j].toInt(), 16 );
                    }
                    QMessageBox::information(0,"",temp);
                }

                PMIB_IPFORWARDTABLE pIpForwardTable = NULL;
                PMIB_IPFORWARDROW pRow = NULL;
                DWORD dwSize = 0;
                BOOL bOrder = FALSE;
                DWORD dwStatus = 0;

                DWORD NewGateway = QStringToDWORD(temp);  // this is in host order Ip Address AA.BB.CC.DD is DDCCBBAA

                unsigned int i;

            // Find out how big our buffer needs to be.
                dwStatus = GetIpForwardTable(pIpForwardTable, &dwSize, bOrder);
                if (dwStatus == ERROR_INSUFFICIENT_BUFFER)
                {
                    // Allocate the memory for the table
                    if (!(pIpForwardTable = (PMIB_IPFORWARDTABLE) malloc(dwSize)))
                    {
                        return "Malloc failed. Out of memory.\n";
                    }
                    // Now get the table.
                    dwStatus = GetIpForwardTable(pIpForwardTable, &dwSize, bOrder);
                }

                if (dwStatus != ERROR_SUCCESS)
                {
                    if (pIpForwardTable)
                        free(pIpForwardTable);
                    return "getIpForwardTable failed.\n";
                }
                // Search for the row in the table we want. The default gateway has a destination
                // of 0.0.0.0. Notice that we continue looking through the table, but copy only
                // one row. This is so that if there happen to be multiple default gateways, we can
                // be sure to delete them all.
                for (i = 0; i < pIpForwardTable->dwNumEntries; i++)
                {
                    if (pIpForwardTable->table[i].dwForwardDest == 0)
                    {
                        // We have found the default gateway.
                        if (!pRow)
                        {
                            // Allocate some memory to store the row in; this is easier than filling
                            // in the row structure ourselves, and we can be sure we change only the
                            // gateway address.
                            pRow = (PMIB_IPFORWARDROW) malloc(sizeof (MIB_IPFORWARDROW));
                            if (!pRow)
                            {
                                return "Malloc failed. Out of memory.\n";
                            }
                            // Copy the row
                            memcpy(pRow, &(pIpForwardTable->table[i]),sizeof (MIB_IPFORWARDROW));
                        }
                        // Delete the old default gateway entry.
                        dwStatus = DeleteIpForwardEntry(&(pIpForwardTable->table[i]));

                        if (dwStatus != ERROR_SUCCESS)
                        {
                          return "Could not delete old gateway\n";
                        }
                    }
                }

                // Set the nexthop field to our new gateway - all the other properties of the route will
                // be the same as they were previously.
                pRow->dwForwardNextHop = NewGateway;

                // Create a new route entry for the default gateway.
                dwStatus += CreateIpForwardEntry(pRow);

                if (dwStatus == NO_ERROR)
                    answer="Gateway changed successfully\n";
                else if (dwStatus == ERROR_INVALID_PARAMETER)
                    answer+="Invalid parameter.\n";
                else
                    answer+="Error:" + dwStatus;

                // Free resources
                if (pIpForwardTable)
                    free(pIpForwardTable);
                if (pRow)
                    free(pRow);

                answer+="Ok";*/

                #else

                bool error=false;
                QString gateWay = prop[i].section(':', 1);

                int sockfd;
                struct rtentry rt;



                   sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                   if (sockfd == -1)
                   {
                       return answer="socket creation failed\n";
                   }

                   struct sockaddr_in *sockinfo = (struct sockaddr_in *)&rt.rt_gateway;
                   sockinfo->sin_family = AF_INET;
                   sockinfo->sin_addr.s_addr = inet_addr(gateWay.toUtf8().data());

                   sockinfo = (struct sockaddr_in *)&rt.rt_dst;
                   sockinfo->sin_family = AF_INET;
                   sockinfo->sin_addr.s_addr = INADDR_ANY;

                   sockinfo = (struct sockaddr_in *)&rt.rt_genmask;
                   sockinfo->sin_family = AF_INET;
                   sockinfo->sin_addr.s_addr = INADDR_ANY;

                   rt.rt_flags = RTF_UP | RTF_GATEWAY;
                   rt.rt_dev = ls[id].humanReadableName().toUtf8().data();

                   if(ioctl(sockfd, SIOCADDRT, &rt) < 0 )
                        answer=strerror(errno);
                   else
                        answer="Ok";

                #endif
