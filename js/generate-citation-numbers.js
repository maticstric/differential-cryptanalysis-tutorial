$('#bibliography li').each((index, element) => {
  let id = $(element).prop('id');
  let citeRegex = new RegExp(`{cite\\(${id}\\)}`, 'g');

  $('#content p').each((_, element) => {
    $(element).html(() => {
      return $(element).html().replace(citeRegex, `<a href="#${id}">[${index + 1}]</a>`);
    });
  });
});
