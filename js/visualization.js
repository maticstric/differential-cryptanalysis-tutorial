let notHexRegex = /[^0-9a-f]/g;

// Get PBOX from the input
const getPBOX = (visualizationId) => {
  let PBOX = [];
  let valid = true;

  $(`#${visualizationId} > .controls > .pbox input`).each((index, element) => {
    if (element.value == '' || element.value.match(notHexRegex) || PBOX.includes(element.value)) {
      valid = false;
    }

    PBOX.push(element.value);
  });

  return (valid ? PBOX : null);
}

// Get SBOX from the input
const getSBOX = (visualizationId) => {
  let SBOX = [];
  let valid = true;

  $(`#${visualizationId} > .controls > .sbox input`).each((index, element) => {
    if (element.value == '' || element.value.match(notHexRegex) || SBOX.includes(element.value)) {
      valid = false;
    }

    SBOX.push(element.value);
  });

  return (valid ? SBOX : null);
}

const restrictInput = (event, len) => {
  if (event.target.value.match(notHexRegex)) {
    event.target.value = event.target.value.replace(notHexRegex, '');
  }

  if (event.target.value.length > len) {
    event.target.value = event.target.value.substring(0, len);
  }
}

const highlightSvgLine = (visualizationId, step, stepClass) => {
  step.forEach((bit, index) => {
    index = index.toString(16);

    if (bit === 1) {
      $(`#${visualizationId} > .figure > svg .${stepClass} .b${index}`).addClass('isOne');
    }
  });
}
