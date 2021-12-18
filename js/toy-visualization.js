const toyHighlightSvgLines = (steps) => {
  // Reset all
  $('#toy-visualization > .figure > svg line').removeClass('isOne');

  let stepsInBinary = steps.map(step => nibbleToBits(step));

  highlightSvgLine('toy-visualization', stepsInBinary[0], 'x');
  highlightSvgLine('toy-visualization', stepsInBinary[1], 'u');
  highlightSvgLine('toy-visualization', stepsInBinary[2], 'v');
  highlightSvgLine('toy-visualization', stepsInBinary[3], 'y');
}

const toyShowEncryption = () => {
  let plaintext = $('#toy-visualization > .controls > .plaintext-key-ciphertext .plaintext-input').val();
  let key1 = $('#toy-visualization > .controls > .plaintext-key-ciphertext .key1-input').val();
  let key2 = $('#toy-visualization > .controls > .plaintext-key-ciphertext .key2-input').val();

  // Put everything into the correct format, which is an array of nibbles
  plaintext = parseInt(plaintext.padStart(1, '0'), 16);
  key1 = parseInt(key1.padStart(1, '0'), 16);
  key2 = parseInt(key2.padStart(1, '0'), 16);

  let sbox = getSBOX('toy-visualization');
  if (sbox === null) { return; }
  sbox = sbox.map(n => parseInt(n, 16));

  let steps = toyEncryptWithSteps(plaintext, sbox, key1, key2);

  // Show ciphertext in controls
  let ciphertextHex = steps[steps.length - 1].toString(16);
  $('#toy-visualization > .controls > .plaintext-key-ciphertext .ciphertext-output').text(`0x${ciphertextHex}`);

  // Show ciphertext below svg
  let nibble1 = parseInt(ciphertextHex, 16).toString(2).padStart(4, '0');
  $('#toy-visualization > .figure > .ciphertext > .nibble1').text(nibble1);

  toyHighlightSvgLines(steps);
}

$(`#toy-visualization > .controls > .plaintext-key-ciphertext .key1-input,
   #toy-visualization > .controls > .plaintext-key-ciphertext .key2-input`).on('input', (event) => {
  restrictInput(event, 1);

  toyShowEncryption();
});

// Put plaintext from input to top of diagram
$('#toy-visualization > .controls > .plaintext-key-ciphertext .plaintext-input').on('input', (event) => {
  restrictInput(event, 1);
  let value = event.target.value.padStart(1, '0');

  let nibble1 = parseInt(value[0], 16).toString(2).padStart(4, '0');

  $('#toy-visualization > .figure > .plaintext > .nibble1').text(nibble1);

  toyShowEncryption();
});

$('#toy-visualization > .controls > .sbox input').on('input', (event) => {
  restrictInput(event, 1);

  let SBOX = getSBOX('toy-visualization');

  if (SBOX !== null) {
    $('#toy-visualization > .controls > .error-messages > .sbox-error').hide();

    toyShowEncryption();
  } else {
    $('#toy-visualization > .controls > .error-messages > .sbox-error').show();
  }
});

// Show encryption on startup
toyShowEncryption();
