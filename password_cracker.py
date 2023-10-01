import hashlib


def get_hash(hash_str):
  hash_str_line = hash_str.strip()
  hash_str_line_encoded = hash_str_line.encode()
  hash_digest = hashlib.sha1(hash_str_line_encoded)
  hash_digest_hexdigest = hash_digest.hexdigest()
  return hash_digest_hexdigest


def crack_sha1_hash(hash, **kwargs):
  useSalt = False
  if kwargs is not None:
    for argument, name in kwargs.items():
      useSalt = name

  with open("known-salts.txt", "r") as salts:
    saltLines = salts.readlines()

  with open("top-10000-passwords.txt", "r") as file:
    contents = file.readlines()

  linecount = 0
  saltcount = 0
  find = False

  testHash = ""

  if (useSalt is True):
    saltcount = 0
    for saltLine in saltLines:
      if find is False:
        linecount = 0
        for line in contents:
          linecount += 1
          saltLineStrip = saltLine.strip()
          testHash = get_hash(saltLineStrip + line.strip())
          if (testHash != hash):
            testHash = get_hash(line.strip() + saltLineStrip)
          if (testHash == hash):
            find = True
            break
        saltcount += 1
  else:
    linecount = 0
    for line in contents:
      linecount += 1
      hash_digest = get_hash(line)
      if (hash_digest == hash):
        break

  if (linecount < 10000):
    result = contents[linecount - 1].strip()
    return result
  else:
    return "PASSWORD NOT IN DATABASE"
