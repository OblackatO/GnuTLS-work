import subprocess
import re
import time


TOTAL_KEYS = 0

def gather_parts(piece_parts: str) -> str:
    """
    Parts of the output from certtool need to be put
    together, in one only variable.
    """
    piece = ""
    for x in piece_parts:
        if x != "":
            piece += x
    return piece


def dissect_certtool_output(key_parts: str, time: str) -> str:
    """
    The information required about each generated key is 
    dissected and gathered. 
    """
    m_a, m_b = key_parts.find('modulus:'), key_parts.find('public exponent:')
    modulus_parts = key_parts[m_a:m_b].replace("modulus:", "").split("\n\t")
    pe_a, pe_b = key_parts.find('public exponent:'), key_parts.find('private exponent:')
    public_exponent_parts = key_parts[pe_a:pe_b].replace("public exponent:", "").split("\n\t")
    p1_a, p1_b = key_parts.find('prime1:'), key_parts.find('prime2:')
    first_prime_parts = key_parts[p1_a:p1_b].replace("prime1:", "").split("\n\t")
    p2_a, p2_b = key_parts.find('prime2:'), key_parts.find('coefficient:')
    second_prime_parts = key_parts[p2_a:p2_b].replace("prime2:", "").split("\n\t")
    pvexp_a, pvexp_b = key_parts.find('private exponent:'), key_parts.find('prime1:')
    private_exponent_parts = key_parts[pvexp_a:pvexp_b].replace("private exponent:", "").split("\n\t")
    global TOTAL_KEYS
    TOTAL_KEYS += 1
    line = str(TOTAL_KEYS)+";"+gather_parts(modulus_parts)+";"+\
        gather_parts(public_exponent_parts)+";"+\
        gather_parts(first_prime_parts)+";"+\
        gather_parts(second_prime_parts)+";"+\
        gather_parts(private_exponent_parts)+";"+\
        time
    line = line.replace("\n", "")
    # print("Line that is going to the file: {}".format(line))
    return line


def generate_keys(key_size: int):
    """
    Launches the certtool command necessary to generate
    some RSA key, of size key_size.
    """
    file_name = "RSA"+str(key_size)+"_results.csv"
    with open(file_name, 'w') as csvfile:
        csvfile.write("id;modulus;public exponent;first prime;second prime;private exponent;time to generate key (ns)\n")
    if key_size == 512:
        max_range = 10**6
    else:
        max_range = 10**4
    for x in range(0,max_range):
        command = ["certtool", "--generate-privkey", "--bits="+str(key_size)]
        initial_time = time.time() 
        command = subprocess.run(command, stdout=subprocess.PIPE)
        key_parts = command.stdout.decode()
        final_time = time.time()
        final_result = final_time - initial_time
        final_result = float(final_result) * 10**9 # The time should be in nanoseconds.
        line = dissect_certtool_output(key_parts, str(final_result))
        if x > 0:
            line = "\n"+line
        with open(file_name, 'a') as csvfile:
            csvfile.write(line)
    

def main():
    generate_keys(512)
    generate_keys(1024)
    generate_keys(2048)

if __name__ == "__main__":
    main()
