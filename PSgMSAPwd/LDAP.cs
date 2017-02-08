using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices.Protocols;
using System.DirectoryServices;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;


namespace psGMSA
{
    class LDAP
    {
        public LdapConnection theConn;
        public string SchemaDN;
        public string ConfigDN;
        public string DomainDN;
        public string dnsHostName;
        public string ntDsDsa;
        public string DSserverName;
        public List<string> AppPartitions = new List<string>();
        public bool bIsADLDS = false;

        //we assume defalt query policy and get the datas...  //this requires auth  =(
        public int MaxValRange = 1500;
        public int MaxPageSize = 1000;

        LdapDirectoryIdentifier LDI;


        public LDAP(LdapDirectoryIdentifier inConn)
        {
            LDI = inConn;
            theConn = new LdapConnection(inConn);
            theConn.AuthType = AuthType.Anonymous; //anon needed to get rootDSE

            theConn.Timeout = new TimeSpan(0, 15, 0);
            getRootDSEData();

            //switch to an auth'd context
            theConn.Dispose();
            theConn = new LdapConnection(inConn);
            //add creds
            
            theConn.AuthType = AuthType.Negotiate;
            theConn.SessionOptions.RootDseCache = true;
            theConn.Timeout = new TimeSpan(0, 15, 0);
            theConn.SessionOptions.SendTimeout = new TimeSpan(0, 15, 0);
            theConn.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            theConn.SessionOptions.Signing = true;
            theConn.SessionOptions.Sealing = true; //the key to getting back password blobs and encryption...
            try
            {
                theConn.Bind();
            }
            catch (Exception ex)
            {
                throw new Exception("LDAP Test Bind failed", ex);
            }
        }

        /// <summary>
        /// Adds a new SID to the SD that controls access to read the password blob
        /// </summary>
        /// <param name="currentSddlBytes">current SDDL SD</param>
        /// <param name="newSID">sid as string, SDDL form</param>
        /// <returns>bigger SD bytes</returns>
        public byte[] addSIDtoSD(byte[] currentSddlBytes, string newSID)
        {
            ActiveDirectorySecurity ads = new ActiveDirectorySecurity();
            SecurityIdentifier realSID = new SecurityIdentifier(newSID);

            byte[] sddlOut = new byte[2];

            try
            {
                ads.SetSecurityDescriptorBinaryForm(currentSddlBytes);
                AuthorizationRuleCollection bb = ads.GetAccessRules(true, true, typeof(SecurityIdentifier));
                bool bAlreadyInSD = false;

                //skip the add if the SID is already on the list
                foreach (AuthorizationRule ar in bb)
                {

                    if (ar.IdentityReference.Value.ToString() == realSID.ToString())
                    {
                        bAlreadyInSD = true;
                        break;
                    }
                }

                if (!bAlreadyInSD)
                {
                    //add it to the SD
                    ads.AddAccessRule(new ActiveDirectoryAccessRule(realSID, ActiveDirectoryRights.GenericAll, AccessControlType.Allow));

                    //output the new SD in bytes
                    sddlOut = ads.GetSecurityDescriptorBinaryForm();
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return sddlOut;
        }

        public List<string> readgMSAPwdReadersACL(byte[] currentSddlBytes)
        {
            List<string> readers = new List<string>();

            ActiveDirectorySecurity ads = new ActiveDirectorySecurity();


            try
            {
                ads.SetSecurityDescriptorBinaryForm(currentSddlBytes);
                AuthorizationRuleCollection bb = ads.GetAccessRules(true, true, typeof(SecurityIdentifier));


                //skip the add if the SID is already on the list
                foreach (AuthorizationRule ar in bb)
                {
                    //get SID
                    string acctName = ar.IdentityReference.Value.ToString();
                    try
                    {
                        //try and resolve to Account
                        IdentityReference dude = ar.IdentityReference;
                        acctName = dude.Translate(typeof(NTAccount)).ToString();


                    }
                    catch (Exception ex)
                    {

                    }

                    readers.Add(acctName);

                   
                }


            }
            catch (Exception ex)
            {
                throw ex;
            }

            return readers;
        }



        /// <summary>
        /// Gets the SD holding those who can read the password blob
        /// </summary>
        /// <param name="acctName">samaccountname</param>
        /// <returns>binary SD</returns>
        public byte[] getgMSAPwdReaders(string acctName)
        {
            try
            {

                string ldapSearchFilter = string.Format("(|(sAMAccountName={0})(sAMAccountName={0}$))", acctName);
                string[] attribs = new string[] { "name",
                            "msDS-GroupMSAMembership"                           };

                // create a SearchRequest object
                SearchRequest searchRequest = new SearchRequest
                                                (this.DomainDN, ldapSearchFilter,
                                                 System.DirectoryServices.Protocols.SearchScope.Subtree, attribs);

                //      30 84 00 00 00 03 02 01 07
                byte[] OIDVal = new byte[] { 0x30, 0x84, 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x07 };
                DirectoryControl editSDOid = new DirectoryControl("1.2.840.113556.1.4.801", OIDVal, false, true);
                searchRequest.Controls.Add(editSDOid);

                //for really slow DCs
                searchRequest.TimeLimit = new TimeSpan(0, 5, 0);

                // cast the directory response into a
                // SearchResponse object
                SearchResponse searchResponse =
                    (SearchResponse)theConn.SendRequest(searchRequest);

                if (searchResponse.Entries.Count == 0)
                {
                    return null;
                }

                // display the entries within this page
                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    SearchResultAttributeCollection attributes = entry.Attributes;

                    foreach (DirectoryAttribute currentAtt in attributes.Values)
                    {
                        string attName = currentAtt.Name.ToLower();

                        switch (attName)
                        {

                            case "msds-groupmsamembership":
                                byte[] sdsad = (byte[])currentAtt[0];
                                return sdsad;
                                break;
                        }
                    }
                }
            }
            catch (DirectoryOperationException odxe)
            {
                throw odxe;
            }

            catch (DirectoryException dex)
            {
                throw dex;
            }

            catch (Exception e)
            {
                throw e;
            }

            return null;

        }

        /// <summary>
        /// Sets the new security descriptor on an account
        /// </summary>
        /// <param name="acctName">samaccountname</param>
        /// <param name="newSD">binary SD</param>
        /// <returns>true/false</returns>
        public bool setgMSAPwdReaders(string acctName, byte[] newSD)
        {
            string dn = getDNFromSamAccountName(acctName);
            if (dn != "")
            {

                //make and send req
                ModifyRequest mReq = new ModifyRequest(dn, DirectoryAttributeOperation.Replace, "msDS-GroupMSAMembership", newSD);

                try
                {
                    ModifyResponse mResp = (ModifyResponse)theConn.SendRequest(mReq);
                    if (mResp.ResultCode == ResultCode.Success)
                    {
                        return true;
                    }
                }
                catch (DirectoryOperationException dox)
                {
                    throw dox;
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }

            return false;
        }


        /// <summary>
        /// Gets the DN of an object by samAccountName.  Looks with and without the trailing$
        /// </summary>
        /// <param name="acctName"></param>
        /// <returns>DN</returns>
        public string getDNFromSamAccountName(string acctName)
        {
            try
            {
                //look for accoutn with or without $
                string ldapSearchFilter = string.Format("(|(sAMAccountName={0})(sAMAccountName={0}$))", acctName);
                SearchRequest sr = new SearchRequest(this.DomainDN,
                    ldapSearchFilter,
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    new string[] { "samaccountname" });

                SearchResponse sresp = (SearchResponse)theConn.SendRequest(sr);
                if (sresp.Entries.Count > 0)
                {
                    return sresp.Entries[0].DistinguishedName;
                }

            }
            catch (Exception ex)
            {
                throw ex;
            }

            return "";

        }

        /// <summary>
        /// get the AD naming contexts from RootDSE, and otehr useful data
        /// </summary>
        private void getRootDSEData()
        {
            try
            {


                // this search filter does not limit the returned results
                string ldapSearchFilter = "(objectClass=*)";

                SearchRequest searchRequest = new SearchRequest(null,
                                                 ldapSearchFilter, System.DirectoryServices.Protocols.SearchScope.Base, null);

                // cast the directory response into a
                // SearchResponse object
                SearchResponse searchResponse =
                    (SearchResponse)theConn.SendRequest(searchRequest);


                // display the entries within this page
                foreach (SearchResultEntry entry in searchResponse.Entries)
                {

                    // start getting attribs from objects in the page
                    SearchResultAttributeCollection attributes = entry.Attributes;

                    foreach (DirectoryAttribute currentsn in attributes.Values)
                    {
                        string dn = entry.DistinguishedName;
                        string attribName = currentsn.Name;

                        if (attribName == "defaultNamingContext")
                        {
                            DomainDN = currentsn[0].ToString();
                        }
                        if (attribName.ToLower() == "dnshostname")
                        {
                            dnsHostName = currentsn[0].ToString();
                        }
                        if (attribName == "configurationNamingContext")
                        {
                            ConfigDN = currentsn[0].ToString();
                        }

                        if (attribName == "schemaNamingContext")
                        {
                            SchemaDN = currentsn[0].ToString();
                        }

                        if (attribName == "namingContexts")
                        {
                            string[] vals = (string[])currentsn.GetValues(typeof(string));
                            AppPartitions.AddRange(vals);
                        }

                        //supportedCapabilities try to ID LDS vs AD
                        if (attribName == "supportedCapabilities")
                        {
                            string[] vals = (string[])currentsn.GetValues(typeof(string));
                            if (vals.Contains("1.2.840.113556.1.4.1851"))
                            {
                                bIsADLDS = true;
                            }
                        }

                        //dsServiceName
                        if (attribName == "dsServiceName")
                        {
                            ntDsDsa = currentsn[0].ToString();
                        }

                        // serverName
                        if (attribName == "serverName")
                        {
                            DSserverName = currentsn[0].ToString();
                        }
                    }
                }
            }
            catch (DirectoryException dex)
            {
                throw new Exception("Failed to get RootDSE. Probably a bad domain name or no transport.", dex);
            }
            catch (Exception e)
            {
                Console.WriteLine("\nDuring get naming Contexts, Unexpected exception occured:\n\t{0}: {1}",
                                  e.GetType().Name, e.Message);

                if (e.Message == "The LDAP server is unavailable.")
                {
                    Console.WriteLine("Probably no path to the server");
                    throw e;
                }
                throw e;
            }
            finally
            {
                AppPartitions.Remove(ConfigDN);
                AppPartitions.Remove(SchemaDN);
            }

        }

        /// <summary>
        /// Get the password blob
        /// </summary>
        /// <param name="acctName">samAccountName</param>
        /// <returns>blob</returns>
        public byte[] getgMSAPwdBlob(string acctName)
        {
            try
            {
                //this is the filter that the ADWS issues , so why not??
                string ldapSearchFilter = "(&(|(sAMAccountName=" + acctName + ")(sAMAccountName=" + acctName + "$))(|(&(objectClass=msDS-ManagedServiceAccount)(objectCategory=msDS-ManagedServiceAccount))(objectClass=msDS-GroupManagedServiceAccount)))"; //we get all computers, just in case
                string[] attribs = new string[] { "sAMAccountName", "msDS-ManagedPassword" };

                // create a SearchRequest object
                SearchRequest searchRequest = new SearchRequest
                                                (this.DomainDN, ldapSearchFilter,
                                                 System.DirectoryServices.Protocols.SearchScope.Subtree, attribs);

                //not needed!
                //     byte[] OIDVal = new byte[] { 0x30, 0x84, 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x07 };
                //      DirectoryControl editSDOid = new DirectoryControl("1.2.840.113556.1.4.801", OIDVal, false, true);
                //       searchRequest.Controls.Add(editSDOid);

                //for really slow DCs
                searchRequest.TimeLimit = new TimeSpan(0, 5, 0);

                // cast the directory response into a
                // SearchResponse object
                SearchResponse searchResponse =
                    (SearchResponse)theConn.SendRequest(searchRequest);

                if (searchResponse.Entries.Count == 0)
                {
                    throw new Exception("The account was not found. It may not be a gMSA or you have the name wrong");
                    return null;
                }

                // display the entries within this result
                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    SearchResultAttributeCollection attributes = entry.Attributes;

                    if (attributes.Count == 1)
                    {
                        throw new Exception("Unable to retrieve the password.  You may not have the rights");
                    }

                    foreach (DirectoryAttribute currentAtt in attributes.Values)
                    {
                        string attName = currentAtt.Name.ToLower();
                        switch (attName)
                        {
                            //msDS-ManagedPassword
                            case "msds-managedpassword":
                                byte[] sdsad = (byte[])currentAtt[0];

                                return sdsad;
                                break;

                        }
                    }
                }
            }
            catch (DirectoryOperationException odxe)
            {
                throw odxe;
            }

            catch (DirectoryException dex)
            {
                throw dex;
            }
            catch (Exception e)
            {
                throw new Exception("Failed to get the gMSA Password from AD.  See innner exception", e);
            }

            return null;

        }


        /// <summary>
        /// Test an AD account password
        /// </summary>
        /// <param name="ldi">an LdapDirectoryIdentifier</param>
        /// <param name="userName">name of user</param>
        /// <param name="password">the password</param>
        /// <param name="domain">the domain name</param>
        /// <returns>true/false</returns>
        public static bool testPassword(LdapDirectoryIdentifier ldi, string userName, string password, string domain)
        {
            LdapConnection tConn = new LdapConnection(ldi);

            try
            {

                tConn.Credential = new System.Net.NetworkCredential(userName + "$", password, domain);
                tConn.Bind();
                tConn.Dispose();
                return true;
            }
            catch (Exception ex)
            {

            }
            tConn.Dispose();
            return false;
        }

    }


    //https://msdn.microsoft.com/en-us/library/hh881234.aspx
    public class msDSManagedPassword
    {

        public short Version
        {
            get;
            set;
        }


        public string CurrentPassword
        {
            get;
            set;
        }


        public string OldPassword
        {
            get;
            set;
        }


        public DateTime dtNextQueryTime
        {
            get;
            set;
        }


        public DateTime dtPwdGoodUntil
        {
            get;
            set;
        }

        //https://msdn.microsoft.com/en-us/library/hh881234.aspx
        public msDSManagedPassword(byte[] blob)
        {

            using (Stream stream = new MemoryStream(blob))
            {
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    this.Version = reader.ReadInt16();

                    short reserved = reader.ReadInt16();

                    //size of blob
                    int length = reader.ReadInt32();

                    if (length != blob.Length)
                    {
                        throw new Exception("Blob is malsized");
                    }

                    short curPwdOffset = reader.ReadInt16();

                    this.CurrentPassword = getUnicodeString(blob, curPwdOffset);

                    short oldPwdOffset = reader.ReadInt16();
                    if (oldPwdOffset > 0)
                    {
                        this.OldPassword = getUnicodeString(blob, oldPwdOffset);
                    }

                    short queryPasswordIntervalOffset = reader.ReadInt16();
                    long queryPasswordIntervalTicks = BitConverter.ToInt64(blob, queryPasswordIntervalOffset);
                    this.dtNextQueryTime = DateTime.Now + TimeSpan.FromTicks(queryPasswordIntervalTicks);


                    short unchangedPasswordIntervalOffset = reader.ReadInt16();
                    long unchangedPasswordIntervalTicks = BitConverter.ToInt64(blob, unchangedPasswordIntervalOffset);
                    this.dtPwdGoodUntil = DateTime.Now + TimeSpan.FromTicks(unchangedPasswordIntervalTicks);
                }
            }
        }



        public static string getUnicodeString(byte[] blob, int index)
        {


            string stOut = "";

            for (int i = index; i < blob.Length; i += 2)
            {
                char ch = BitConverter.ToChar(blob, i);
                if (ch == Char.MinValue)
                {
                    //found the end  .    A null-terminated WCHAR string
                    return stOut;
                }
                stOut = stOut + ch;


            }

            return null;
        }
    }
}
