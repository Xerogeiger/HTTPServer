interface Job {
    company: string;
    role: string;
    period: string;
    bullets: string[];
}
interface Education {
    institution: string;
    degree: string;
    period: string;
}
interface Project {
    name: string;
    image: string;
    desc: string;
}
interface Skill {
    name: string;
    level: 'beginner' | 'intermediate' | 'advanced';
}

const aboutText = `<p>
    I am a dedicated Software Developer with a passion for designing and delivering
    robust, user‑centric applications. Over the past several years, I’ve built
    full‑stack solutions in Java, C#, and TypeScript—ranging from VR‑based training
    modules to RESTful API backends—always striving for clean code, high performance,
    and maintainability.
  </p>
  <p>
    Beyond coding, I bring strong customer‑facing experience from my role at Home Depot,
    where I honed my communication, problem‑solving, and teamwork skills. I thrive in
    Agile environments, enjoy mentoring peers, and am constantly exploring new
    technologies—most recently Rust.
    I’m eager to take on challenges that blend innovation, collaboration, and continuous
    improvement.
  </p>`;

const experience: Job[] = [
    {
        company: 'Home Depot, Moore, OK',
        role: 'Sales Associate',
        period: 'September 2024 – April 2025',
        bullets: [
            'Assisted customers in locating and purchasing home improvement products.',
            'Provided exceptional customer service by answering questions and offering guidance.',
            'Applied product knowledge in tools, hardware, and building supplies.',
        ],
    },
    {
        company: 'College of Biomedical Equipment Technology',
        role: 'Software Developer',
        period: 'June 2021 – December 2022',
        bullets: [
            'Developed systems to manage education‑related services.',
            'Created VR‑based training modules and educational experiences.',
            'Consulted on hiring, contractor review, and technology choices.',
            'Managed multiple ongoing development projects and met employee needs.',
        ],
    },
];

const education: Education[] = [
    {
        institution: 'Texas Connections Academy at Houston',
        degree: 'High School Diploma',
        period: '2018 – 2021',
    },
    {
        institution: 'Alamo College',
        degree: 'Computer Science Coursework',
        period: 'September 2023 – January 2024',
    },
];

const projects: Project[] = [
    {
        name: 'Student Analysis Program',
        image: 'images/sap-sc.png',
        desc: 'Spring based application for automated reporting of student data and performance.',
    },
    {
        name: 'AMX4 VR Training',
        image: 'video/AMX4-Video.mp4',
        desc: 'Virtual reality modules for hands‑on technical training.',
    },
    {
        name: 'Medrad Injector Training',
        image: 'images/injector-sc.png',
        desc: 'VR training module for medical equipment operation.',
    },
    {
        name: "AI Chatbot",
        image: 'images/ai-sc.png',
        desc: 'A chatbot that uses various locally ran AI models to answer questions and provide information.',
    }
    // add more projects as needed
];

const technicalSkills = [
    {
        name: 'Java',
        level: 'advanced',
    },
    {
        name: 'C#',
        level: 'intermediate',
    },
    {
        name: 'Python',
        level: 'beginner',
    },
    {
        name: 'HTML/CSS/JavaScript',
        level: 'intermediate',
    },
    {
        name: 'Typescript',
        level: 'intermediate',
    },
    {
        name: 'SQL',
        level: 'beginner',
    },
    {
        name: 'Git/GitHub',
        level: 'beginner',
    },
    {
        name: 'Unity3D',
        level: 'advanced',
    },
    {
        name: 'Unreal Engine',
        level: 'intermediate',
    },
    {
        name: 'VR Development',
        level: 'advanced',
    },
    {
        name: 'REST APIs',
        level: 'intermediate',
    },
    {
        name: 'Rust',
        level: 'beginner',
    },
    {
        name: 'C++',
        level: 'intermediate',
    },
    {
        name: 'Spring Boot',
        level: 'intermediate',
    },
];

const otherSkills = [
    'Customer Service: Assisting customers, conflict resolution',
    'Communication & Teamwork: Working with technical and non‑technical teams'
];

const contact = {
    email: 'alexzanderjb@gmail.com',
    linkedin: 'https://www.linkedin.com/in/alexzander-bond-899157333/'
};

function qs<T extends HTMLElement>(sel: string) {
    return document.querySelector(sel) as T;
}

function populate() {
    qs<HTMLParagraphElement>('#about-text').innerHTML = aboutText;

    const expEl = qs<HTMLDivElement>('#experience-list');
    experience.forEach(j => {
        const d = document.createElement('div');
        d.className = 'job';
        d.innerHTML = `
      <h3>${j.role} @ ${j.company}</h3>
      <span class="period">${j.period}</span>
      <div class="experience-bullets"> 
          <ul>${j.bullets.map(b => `<li>${b}</li>`).join('')}</ul>
      </div>
    `;
        expEl.append(d);
    });

    const eduEl = qs<HTMLDivElement>('#education-list');
    education.forEach(e => {
        const d = document.createElement('div');
        d.className = 'edu-entry';
        d.innerHTML = `
      <h3>${e.institution}</h3>
      <span class="period">${e.period}</span>
      <p>${e.degree}</p>
    `;
        eduEl.append(d);
    });

    const techEl = qs<HTMLUListElement>('#skills-list');
    const beginnerDiv = document.createElement('div');
    const beginnerTitle = document.createElement('h3');
    beginnerTitle.textContent = 'Beginner Skills:';
    beginnerDiv.append(beginnerTitle);

    const intermediateDiv = document.createElement('div');
    const intermediateTitle = document.createElement('h3');
    intermediateTitle.textContent = 'Intermediate Skills:';
    intermediateDiv.append(intermediateTitle);

    const advancedDiv = document.createElement('div');
    const advancedTitle = document.createElement('h3');
    advancedTitle.textContent = 'Advanced Skills:';
    advancedDiv.append(advancedTitle);
    techEl.append(beginnerDiv, intermediateDiv, advancedDiv);

    const beginnerSkills = technicalSkills.filter(s => s.level === 'beginner').map(s => s.name);
    const intermediateSkills = technicalSkills.filter(s => s.level === 'intermediate').map(s => s.name);
    const advancedSkills = technicalSkills.filter(s => s.level === 'advanced').map(s => s.name);

    beginnerSkills.forEach(s => {
        const span = document.createElement('span');
        span.textContent = '\t' + s;
        beginnerDiv.append(span);
    });
    beginnerDiv.className = 'beginner';

    intermediateSkills.forEach(s => {
        const span = document.createElement('span');
        span.textContent = '\t' + s;
        intermediateDiv.append(span);
    });
    intermediateDiv.className = 'intermediate';

    advancedSkills.forEach(s => {
        const span = document.createElement('span');
        span.textContent = '\t' + s;
        advancedDiv.append(span);
    });
    advancedDiv.className = 'advanced';

    const otherEl = qs<HTMLUListElement>('#other-skills-list');
    otherSkills.forEach(s => {
        const li = document.createElement('span');
        li.textContent = s;
        otherEl.append(li);
        otherEl.append(document.createElement('br'));
    });

    const emailLink = qs<HTMLAnchorElement>('#email-link');
    emailLink.href = `mailto:${contact.email}`;
    emailLink.textContent = contact.email;

    const liLink = qs<HTMLAnchorElement>('#linkedin-link');
    liLink.href = contact.linkedin;
    liLink.textContent = contact.linkedin;
}

function setupCarousel() {
    let idx = 0;
    const img = qs<HTMLImageElement>('#carousel-image');
    const video = qs<HTMLVideoElement>('#carousel-video');
    const cap = qs<HTMLDivElement>('#carousel-caption');
    const prev = qs<HTMLButtonElement>('#prev');
    const next = qs<HTMLButtonElement>('#next');

    function show(i: number) {
        const p = projects[i];
        img.style.opacity = '0';
        setTimeout(() => {
            if (p.image.endsWith('.mp4')) {
                video.style.display = 'block';
                img.style.display = 'none';
                video.src = p.image;
                video.play().then(() => {
                })
            } else {
                video.style.display = 'none';
                img.src = p.image;
                img.style.display = 'block';
            }
            cap.textContent = `${p.name}: ${p.desc}`;
            img.style.opacity = '1';
        }, 250);
    }

    prev.addEventListener('click', () => {
        idx = (idx - 1 + projects.length) % projects.length;
        show(idx);
    });
    next.addEventListener('click', () => {
        idx = (idx + 1) % projects.length;
        show(idx);
    });
    show(idx);
}

document.addEventListener('DOMContentLoaded', () => {
    populate();
    setupCarousel();
});
