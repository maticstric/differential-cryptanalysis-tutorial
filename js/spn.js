const nibblesToBits = (nibbles) => {
  bits = [];

  nibbles.forEach((nibble) => {
    bits.push((nibble >> 3) & 1);
    bits.push((nibble >> 2) & 1);
    bits.push((nibble >> 1) & 1);
    bits.push(nibble & 1);
  });

  return bits;
}

const bitsToNibbles = (bits) => {
  nibbles = [];

  for (let i = 0; i < bits.length; i += 4) {
    let nibble = bits[i] << 3 | bits[i + 1] << 2 | bits[i + 2] << 1 | bits[i + 3];
    nibbles.push(nibble);
  }

  return nibbles;
}

const spnSubstitute = (state, sbox) => {
  let newState = [];

  state.forEach((element) => {
    newState.push(sbox[element]);
  });

  return newState;
}

const spnPermutate = (state, pbox) => {
  let newStateBits = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

  let stateBits = nibblesToBits(state);

  stateBits.forEach((bit, index) => {
    newStateBits[pbox[index]] = bit;
  });

  return bitsToNibbles(newStateBits);
}

const spnAddRoundKey = (state, key) => {
  let newState = [];

  state.forEach((nibble, index) => {
    newState.push(nibble ^ key[index]);
  });

  return newState;
}

const spnEncrypt = (state, sbox, pbox, key1, key2, key3, key4, key5) => {
  let encryptedState = state.slice();

  encryptedState = spnAddRoundKey(encryptedState, key1);
  encryptedState = spnSubstitute(encryptedState, sbox);
  encryptedState = spnPermutate(encryptedState, pbox);

  encryptedState = spnAddRoundKey(encryptedState, key2);
  encryptedState = spnSubstitute(encryptedState, sbox);
  encryptedState = spnPermutate(encryptedState, pbox);

  encryptedState = spnAddRoundKey(encryptedState, key3);
  encryptedState = spnSubstitute(encryptedState, sbox);
  encryptedState = spnPermutate(encryptedState, pbox);

  encryptedState = spnAddRoundKey(encryptedState, key4);
  encryptedState = spnSubstitute(encryptedState, sbox);

  encryptedState = spnAddRoundKey(encryptedState, key5);

  return encryptedState;
}

const spnDecrypt = (state, invSbox, invPbox, key1, key2, key3, key4, key5) => {
  let decryptedState = state.slice();

  decryptedState = spnAddRoundKey(decryptedState, key5);

  decryptedState = spnSubstitute(decryptedState, invSbox);
  decryptedState = spnAddRoundKey(decryptedState, key4);

  decryptedState = spnPermutate(decryptedState, invPbox);
  decryptedState = spnSubstitute(decryptedState, invSbox);
  decryptedState = spnAddRoundKey(decryptedState, key3);

  decryptedState = spnPermutate(decryptedState, invPbox);
  decryptedState = spnSubstitute(decryptedState, invSbox);
  decryptedState = spnAddRoundKey(decryptedState, key2);

  decryptedState = spnPermutate(decryptedState, invPbox);
  decryptedState = spnSubstitute(decryptedState, invSbox);
  decryptedState = spnAddRoundKey(decryptedState, key1);

  return decryptedState;
}

const spnEncryptWithSteps = (state, sbox, pbox, key1, key2, key3, key4, key5) => {
  let encryptedState = state.slice();
  let steps = [];

  steps.push(encryptedState.slice());

  encryptedState = spnAddRoundKey(encryptedState, key1);
  steps.push(encryptedState.slice());
  encryptedState = spnSubstitute(encryptedState, sbox);
  steps.push(encryptedState.slice());
  encryptedState = spnPermutate(encryptedState, pbox);
  steps.push(encryptedState.slice());

  encryptedState = spnAddRoundKey(encryptedState, key2);
  steps.push(encryptedState.slice());
  encryptedState = spnSubstitute(encryptedState, sbox);
  steps.push(encryptedState.slice());
  encryptedState = spnPermutate(encryptedState, pbox);
  steps.push(encryptedState.slice());

  encryptedState = spnAddRoundKey(encryptedState, key3);
  steps.push(encryptedState.slice());
  encryptedState = spnSubstitute(encryptedState, sbox);
  steps.push(encryptedState.slice());
  encryptedState = spnPermutate(encryptedState, pbox);
  steps.push(encryptedState.slice());

  encryptedState = spnAddRoundKey(encryptedState, key4);
  steps.push(encryptedState.slice());
  encryptedState = spnSubstitute(encryptedState, sbox);
  steps.push(encryptedState.slice());

  encryptedState = spnAddRoundKey(encryptedState, key5);
  steps.push(encryptedState.slice());

  return steps;
}

const spnDecryptWithSteps = (state, invSbox, invPbox, key1, key2, key3, key4, key5) => {
  let decryptedState = state.slice();
  let steps = [];

  steps.push(decryptedState.slice());

  decryptedState = spnAddRoundKey(decryptedState, key5);
  steps.push(decryptedState.slice());

  decryptedState = spnSubstitute(decryptedState, invSbox);
  steps.push(decryptedState.slice());
  decryptedState = spnAddRoundKey(decryptedState, key4);
  steps.push(decryptedState.slice());

  decryptedState = spnPermutate(decryptedState, invPbox);
  steps.push(decryptedState.slice());
  decryptedState = spnSubstitute(decryptedState, invSbox);
  steps.push(decryptedState.slice());
  decryptedState = spnAddRoundKey(decryptedState, key3);
  steps.push(decryptedState.slice());

  decryptedState = spnPermutate(decryptedState, invPbox);
  steps.push(decryptedState.slice());
  decryptedState = spnSubstitute(decryptedState, invSbox);
  steps.push(decryptedState.slice());
  decryptedState = spnAddRoundKey(decryptedState, key2);
  steps.push(decryptedState.slice());

  decryptedState = spnPermutate(decryptedState, invPbox);
  steps.push(decryptedState.slice());
  decryptedState = spnSubstitute(decryptedState, invSbox);
  steps.push(decryptedState.slice());
  decryptedState = spnAddRoundKey(decryptedState, key1);
  steps.push(decryptedState.slice());

  return steps;
}
