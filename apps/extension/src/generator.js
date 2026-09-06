const GROUPS = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%^&*_-+="];
const ALPHABET = GROUPS.join("");

function randomIndex(size, random = crypto) {
  if (!Number.isSafeInteger(size) || size < 1 || size > 256) throw new RangeError("Invalid alphabet size");
  const ceiling = 256 - (256 % size);
  const byte = new Uint8Array(1);
  do random.getRandomValues(byte); while (byte[0] >= ceiling);
  return byte[0] % size;
}

export function generatePassword(length = 24, random = crypto) {
  if (!Number.isSafeInteger(length) || length < 12 || length > 128) throw new RangeError("Password length must be 12–128");
  const characters = GROUPS.map((group) => group[randomIndex(group.length, random)]);
  while (characters.length < length) characters.push(ALPHABET[randomIndex(ALPHABET.length, random)]);
  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swap = randomIndex(index + 1, random);
    [characters[index], characters[swap]] = [characters[swap], characters[index]];
  }
  return characters.join("");
}
