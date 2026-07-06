import base64

input_file = "wl3"
output_file = "wl4"

with open(input_file, "r", encoding="utf-8") as infile, \
     open(output_file, "w", encoding="utf-8") as outfile:

    for line in infile:
        line = line.rstrip("\r\n")  # Remove newline characters
        encoded = base64.b64encode(line.encode("utf-8")).decode("utf-8")
        outfile.write(encoded + "\n")

print(f"Done! Base64-encoded lines written to {output_file}")