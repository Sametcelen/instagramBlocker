document.addEventListener('DOMContentLoaded', () => {
    const particlesDiv = document.querySelector('.particles');
    const particleCount = 50;

    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.style.position = 'absolute';
        particle.style.width = `${Math.random() * 3 + 1}px`;
        particle.style.height = particle.style.width;
        particle.style.background = 'rgba(255, 51, 51, 0.5)';
        particle.style.borderRadius = '50%';
        particle.style.left = `${Math.random() * 100}vw`;
        particle.style.top = `${Math.random() * 100}vh`;
        particle.style.animation = `move ${Math.random() * 10 + 5}s infinite`;
        particlesDiv.appendChild(particle);
    }
});

const style = document.createElement('style');
style.textContent = `
    @keyframes move {
        0% { transform: translate(0, 0); opacity: 0.5; }
        50% { transform: translate(${Math.random() * 200 - 100}px, ${Math.random() * 200 - 100}px); opacity: 1; }
        100% { transform: translate(0, 0); opacity: 0.5; }
    }
`;
document.head.appendChild(style);