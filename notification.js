const title = document.getElementById('title');
const message = document.getElementById('message');

chrome.storage.local.get(['notificationTitle', 'notificationMessage', 'clipboardText'], (data) => {
  title.textContent = data.notificationTitle || 'Operation Completed';
  message.textContent = data.notificationMessage || 'The data has been fetched and processed.';

  navigator.clipboard.writeText(data.clipboardText).then(function() {
    console.log('Copying to clipboard was successful!');
  }, function(err) {
    console.error('Could not copy text: ', err);
  });

  setTimeout(() => {
    window.close();
  }, 2500);
});


