export function lazyLoadImages(): void {
  const images = Array.from(document.querySelectorAll<HTMLImageElement>('img[data-src]'));
  if (!images.length) {
    return;
  }

  const swap = (img: HTMLImageElement) => {
    const dataSrc = img.dataset.src;
    if (!dataSrc) {
      return;
    }
    img.src = dataSrc;
    delete img.dataset.src;
  };

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries, obs) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        const target = entry.target as HTMLImageElement;
        swap(target);
        obs.unobserve(target);
      }
    }, {
      rootMargin: '64px',
    });

    images.forEach((img) => observer.observe(img));
  } else {
    images.forEach(swap);
  }
}
