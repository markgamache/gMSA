using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Management.Automation;
using System.Security;

namespace psGMSA
{
    public class Program
    {
        [STAThreadAttribute]
        static void Main(string[] args)
        {
           

        }

        static public string getGMSAPassword(Cmdlet ni, string account, string domain)
        {
            string pwdToUse = "";

            LdapDirectoryIdentifier ldi = new LdapDirectoryIdentifier(domain, false, false);

            LDAP myLdap = new LDAP(ldi);
            try
            {

                byte[] blob = myLdap.getgMSAPwdBlob(account);


                msDSManagedPassword mPass = new msDSManagedPassword(blob);
                bool bOldPwdGood = LDAP.testPassword(ldi, account, mPass.OldPassword, domain);
                bool bNewPwdGood = LDAP.testPassword(ldi, account, mPass.CurrentPassword, domain);

                if (bOldPwdGood && bNewPwdGood)
                {
                    pwdToUse = mPass.CurrentPassword;
                }

                if (bNewPwdGood && !bOldPwdGood)
                {
                    pwdToUse = mPass.CurrentPassword;
                }

                if (!bNewPwdGood && bOldPwdGood)
                {
                    pwdToUse = mPass.OldPassword;
                    string warn = string.Format("You may want to sit back and wait.  The password will change at {0}", mPass.dtNextQueryTime.ToString("MM-dd-yyyy HH:mm:ss.ff"));
                    ni.WriteWarning(warn);
                }

            }
            catch (Exception ex)
            {
                ni.WriteDebug(ex.Message);
                ni.WriteDebug(ex.InnerException.Message);
                //The account was not found. It may not be a gMSA or you have the name wrong
                //Unable to retrieve the password.  You may not have the rights

                if (ex.Message == "Failed to get the gMSA Password from AD.  See innner exception" && ex.InnerException.Message == "Unable to retrieve the password.  You may not have the rights")
                {
                    //look at the perms on the object
                    byte[] readersACE = myLdap.getgMSAPwdReaders(account);
                    List<string> readers = myLdap.readgMSAPwdReadersACL(readersACE);
                    string ll = stringListToString(readers);

                    throw new Exception("Failed to read the password. It can only be read by " + ll);
                }

                throw new Exception("Getting pwd failed", ex);
            }
            return pwdToUse;
        }

        static public string getGMSAPassword(string account, string domain)
        {
            string pwdToUse = "";

            LdapDirectoryIdentifier ldi = new LdapDirectoryIdentifier(domain, false, false);

            LDAP myLdap = new LDAP(ldi);
            try
            {

                byte[] blob = myLdap.getgMSAPwdBlob(account);


                msDSManagedPassword mPass = new msDSManagedPassword(blob);
                bool bOldPwdGood = LDAP.testPassword(ldi, account, mPass.OldPassword, domain);
                bool bNewPwdGood = LDAP.testPassword(ldi, account, mPass.CurrentPassword, domain);

                if (bOldPwdGood && bNewPwdGood)
                {
                    pwdToUse = mPass.CurrentPassword;
                }

                if (bNewPwdGood && !bOldPwdGood)
                {
                    pwdToUse = mPass.CurrentPassword;
                }

                if (!bNewPwdGood && bOldPwdGood)
                {
                    pwdToUse = mPass.OldPassword;
                    string warn = string.Format("You may want to sit back and wait.  The password will change at {0}", mPass.dtNextQueryTime.ToString("MM-dd-yyyy HH:mm:ss.ff"));
                    // ni.WriteWarning(warn);
                }

            }
            catch (Exception ex)
            {
                //  ni.WriteDebug(ex.Message);
                //  ni.WriteDebug(ex.InnerException.Message);
                //The account was not found. It may not be a gMSA or you have the name wrong
                //Unable to retrieve the password.  You may not have the rights

                if (ex.Message == "Failed to get the gMSA Password from AD.  See innner exception" && ex.InnerException.Message == "Unable to retrieve the password.  You may not have the rights")
                {
                    //look at the perms on the object
                    byte[] readersACE = myLdap.getgMSAPwdReaders(account);
                    List<string> readers = myLdap.readgMSAPwdReadersACL(readersACE);
                    string ll = stringListToString(readers);

                    throw new Exception("Failed to read the password. It can only be read by " + ll);
                }

                throw new Exception("Getting pwd failed", ex);
            }
            return pwdToUse;
        }



        static string stringListToString(List<string> theList)
        {
            string stOut = "";
            foreach (string str in theList)
            {
                stOut += str + ",";
            }
            stOut = stOut.Substring(0, stOut.Length - 1);

            return stOut;
        }
    }


    [Cmdlet("Get", "gMSAPassword")]
    public class getGMSAPassword : Cmdlet
    {

        [Parameter(Mandatory = true, HelpMessage = "The sAMAccountName of the gMSA")]
        public String Name { get; set; }

        [Parameter(Mandatory = false, HelpMessage = "The domain of the account")]
        public string Domain { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "You must pick an output type")]
        public OutPutType Output { get; set; }

        protected override void BeginProcessing()
        {
            string defDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            if (Domain != null)
            {
                defDomain = Domain;
            }

            try
            {
                string thePassword = Program.getGMSAPassword(this, Name, defDomain);
                if (Output == OutPutType.String)
                {
                    WriteObject(thePassword);
                }
                else if (Output == OutPutType.SecureString)
                {
                    //conver to secstring
                    SecureString ss = new SecureString();
                    foreach (char c in thePassword)
                    {
                        ss.AppendChar(c);
                    }
                    WriteObject(ss);
                }
                else if (Output == OutPutType.ClipBoard)
                {
                    Clipboard.SetText(thePassword);
                }
                else if (Output == OutPutType.ByteArray)
                {
                    UnicodeEncoding uc = new UnicodeEncoding();
                    byte[] bOut = uc.GetBytes(thePassword);
                    WriteObject(bOut);

                }
                else if (Output == OutPutType.Credential)
                {
                    //conver to secstring
                    SecureString ss = new SecureString();
                    foreach (char c in thePassword)
                    {
                        ss.AppendChar(c);
                    }

                    PSCredential pc = new PSCredential(defDomain + "\\" + Name + "$", ss);
                    WriteObject(pc);
                }
            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    WriteWarning(ex.InnerException.Message);
                    if (ex.InnerException.InnerException != null)
                    {
                        WriteWarning(ex.InnerException.InnerException.Message);
                    }
                }

                WriteError(new ErrorRecord(ex, "666", ErrorCategory.ReadError, null));
            }

        }
    }


    public enum OutPutType
    {
        String,
        SecureString,
        ClipBoard,
        ByteArray,
        Credential
    }

}
