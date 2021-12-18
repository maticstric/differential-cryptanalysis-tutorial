const nibbleToBits = (nibble) => {
  bits = [];

  bits.push((nibble >> 3) & 1);
  bits.push((nibble >> 2) & 1);
  bits.push((nibble >> 1) & 1);
  bits.push(nibble & 1);

  return bits;
}

const toySubstitute = (state, sbox) => {
  return sbox[state];
}

const toyAddRoundKey = (state, key) => {
  return state ^ key;
}

const toyEncrypt = (state, sbox, key1, key2) => {
  let encryptedState = toyAddRoundKey(state, key1);
  encryptedState = toySubstitute(encryptedState, sbox);
  encryptedState = toyAddRoundKey(encryptedState, key2);

  return encryptedState;
}

const toyDecrypt = (state, invSbox, key1, key2) => {
  let decryptedState = toyAddRoundKey(state, key2);
  decryptedState = toySubstitute(decryptedState, invSbox);
  decryptedState = toyAddRoundKey(decryptedState, key1);

  return decryptedState;
}

const toyEncryptWithSteps = (state, sbox, key1, key2) => {
  let steps = [];

  steps.push(state);

  let encryptedState = toyAddRoundKey(state, key1);
  steps.push(encryptedState);

  encryptedState = toySubstitute(encryptedState, sbox);
  steps.push(encryptedState);

  encryptedState = toyAddRoundKey(encryptedState, key2);
  steps.push(encryptedState);

  return steps;
}

const toyDecryptWithSteps = (state, invSbox, key1, key2) => {
  let steps = [];

  steps.push(state);

  let decryptedState = toyAddRoundKey(state, key2);
  steps.push(decryptedState);

  decryptedState = toySubstitute(decryptedState, invSbox);
  steps.push(decryptedState);

  decryptedState = toyAddRoundKey(decryptedState, key1);
  steps.push(decryptedState);

  return steps;
}
