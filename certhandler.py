import os
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import shutil

class CertificateManagerApp:
    def __init__(self, root):
        self.root = root
        # set openssl.exe path (Win64)! 
        self.openssl_path = "C:/Program Files/OpenSSL-Win64/bin/openssl.exe"
        self.root.title("Certificate Manager")
        
        self.generate_button = tk.Button(root, text="Generate Certificate", command=self.generate_certificate)
        self.generate_button.pack(pady=5)
        
        self.import_button = tk.Button(root, text="Import Certificate", command=self.import_certificate)
        self.import_button.pack(pady=5)
        
        self.cert_details = tk.Text(root, height=10, width=80)
        self.cert_details.pack(pady=5)
        self.cert_details.config(state=tk.DISABLED)
        
        self.check_validity_button = tk.Button(root, text="Check Certificate Validity", command=self.check_validity)
        self.check_validity_button.pack(pady=5)
        
        self.revoke_button = tk.Button(root, text="Revoke Certificate", command=self.revoke_certificate)
        self.revoke_button.pack(pady=5)
        
        self.cert_path = None
        self.crl_path = "./demoCA/crl.pem"

    # runs tkinter
    def run_command(self, command):
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            return result.stderr
        return result.stdout

    # creates the needed directory structure (for revoking specifically)
    def create_dir_structure(self, ca_dir):
        os.makedirs(ca_dir)
        os.makedirs(os.path.join(ca_dir, "newcerts"))
        open(os.path.join(ca_dir, "index.txt"), 'a').close()
        with open(os.path.join(ca_dir, "serial"), 'w') as serial_file:
            serial_file.write("1000")
        with open(os.path.join(ca_dir, "crlnumber"), 'w') as crl_number_file:
            crl_number_file.write("01")

    # generates a new certificate, csr and key, then signs certificate
    def generate_certificate(self):
        ca_dir = "./demoCA"
        if not os.path.exists(ca_dir):
            self.create_dir_structure(ca_dir)
        
        # removes crl.pem with backup if exists
        if os.path.exists(self.crl_path):
            crl_old_path = os.path.join("./demoCA", "crlold.pem")
            shutil.copyfile(self.crl_path, crl_old_path)
            os.remove(self.crl_path)
            self.crl_path = None

        private_key = "private.key"
        csr = "request.csr"
        cert = "certificate.crt"
        
        self.run_command([self.openssl_path, "genpkey", "-algorithm", "RSA", "-out", private_key])
        self.run_command([self.openssl_path, "req", "-new", "-key", private_key, "-out", csr, "-subj", "/CN=localhost"])
        self.run_command([self.openssl_path, "req", "-x509", "-key", private_key, "-in", csr, "-out", cert, "-days", "365"])
        
        messagebox.showinfo("Success", "Certificate generated and signed successfully.")
        
        with open(cert, 'r') as cert_file:
            cert_data = cert_file.read()
        
        self.cert_details.config(state=tk.NORMAL)
        self.cert_details.delete(1.0, tk.END)
        self.cert_details.insert(tk.END, cert_data)
        self.cert_details.config(state=tk.DISABLED)
        
        self.cert_path = cert

    # sets certificate into textbox / program
    def import_certificate(self):
        cert_path = filedialog.askopenfilename(title="Select Certificate", filetypes=[("Certificate Files", "*.crt")])
        if cert_path:
            with open(cert_path, 'r') as cert_file:
                cert_data = cert_file.read()
            
            self.cert_details.config(state=tk.NORMAL)
            self.cert_details.delete(1.0, tk.END)
            self.cert_details.insert(tk.END, cert_data)
            self.cert_details.config(state=tk.DISABLED)
            
            self.cert_path = cert_path
    
    # cheks whether certificate is still valid by checking pem file
    def check_validity(self):
        if self.cert_path:
            crl_path = "./demoCA/crl.pem"
            if os.path.exists(crl_path):
                result = self.run_command([self.openssl_path, "verify", "-CAfile", self.cert_path, "-crl_check", "-CRLfile", crl_path, self.cert_path])
                if "error" in result.lower():
                    messagebox.showerror("Certificate Validity Error", result)
            else:
                messagebox.showinfo("Info", "Certificate OK.")
        else:
            messagebox.showwarning("Warning", "Import certificate first.")

    # revokes the certificate and makes .pem file
    # when generating new certificate, this .pem file will be written into crlold.pem
    def revoke_certificate(self):
        if self.cert_path:
            ca_key_path = filedialog.askopenfilename(title="Select CA Key", filetypes=[("Key Files", "*.key")])
            
            if ca_key_path:
                self.run_command([self.openssl_path, "ca", "-revoke", self.cert_path, "-keyfile", ca_key_path, "-cert", self.cert_path])
                self.run_command([self.openssl_path, "ca", "-gencrl", "-out", os.path.join("./demoCA", "crl.pem"), "-keyfile", ca_key_path, "-cert", self.cert_path])
                messagebox.showinfo("Success", "Certificate revoked successfully.")
                
                self.crl_path = os.path.join("./demoCA", "crl.pem")
            else:
                messagebox.showwarning("Warning", "Select CA key.")
        else:
            messagebox.showwarning("Warning", "Import a certificate first.")

if __name__ == "__main__":
    root = tk.Tk()
    app = CertificateManagerApp(root)
    root.mainloop()
