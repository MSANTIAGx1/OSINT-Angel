const title = document.getElementById('title');
const message = document.getElementById('message');

chrome.storage.local.get(['notificationTitle', 'notificationMessage'], (data) => {
  title.textContent = data.notificationTitle || 'Operation Completed';
  message.textContent = data.notificationMessage || 'The data has been fetched and processed.';
  

  setTimeout(() => {
    window.close();
  }, 1500);
});