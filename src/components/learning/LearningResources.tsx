import React from 'react';
import { ExternalLink, Target, Compass, BookOpen, Cloud, Shield, Award, Terminal } from 'lucide-react';
import { Explainer } from '../Explainer.tsx';

export const LearningResources: React.FC = () => {
  const platforms = [
    {
      name: 'TryHackMe (THM)',
      category: 'Guided Hands-on Labs & Fundamentals',
      description:
        'Browser-based virtual machines with guided question-and-answer rooms. Perfect for structured daily learning without complex local setup.',
      recommendedPaths: [
        'Pre-Security Pathway (Networking, Linux, Web basics)',
        'Complete Beginner Pathway (Linux fundamentals, Cryptography)',
        'SOC Level 1 Pathway (Splunk, Wireshark, Incident Response)',
        'AWS & Cloud Security Basics',
      ],
      url: 'https://tryhackme.com',
      badge: 'Beginner to Intermediate',
    },
    {
      name: 'PortSwigger Web Security Academy',
      category: 'Web Application Security & OWASP Top 10',
      description:
        'Created by the creators of Burp Suite. Contains 100% free, high-quality interactive labs covering SQL injection, XSS, SSRF, CSRF, and authentication bypasses.',
      recommendedPaths: [
        'Server-Side Vulnerabilities (SQLi, Directory Traversal, Command Injection)',
        'Client-Side Topics (XSS, CSRF, CORS, Clickjacking)',
        'Advanced Topics (HTTP Request Smuggling, OAuth authentication flaws)',
      ],
      url: 'https://portswigger.net/web-security',
      badge: 'Industry Standard (Free)',
    },
    {
      name: 'OverTheWire: Bandit',
      category: 'Linux Command-Line Mastery',
      description:
        'A gamified SSH wargame where you solve 34 progressively harder levels to find passwords hidden in file systems, compressed archives, and encrypted network sockets.',
      recommendedPaths: [
        'Bandit (Essential Linux CLI navigation, grep, piping, base64, SSH keys)',
        'Natas (Server-side web security mechanics)',
      ],
      url: 'https://overthewire.org/wargames/bandit/',
      badge: 'Foundational Linux CLI',
    },
    {
      name: 'Hack The Box (HTB)',
      category: 'Challenging CTF Machines & HTB Academy',
      description:
        'Realistic enterprise networks and active challenge machines. Great for testing your independence once you understand core networking and scripting.',
      recommendedPaths: [
        'Starting Point Tier (Tier 0 to Tier 2 machines)',
        'HTB Academy: Linux Fundamentals & Information Security Foundations',
        'Certified Penetration Testing Specialist (CPTS) Modules',
      ],
      url: 'https://www.hackthebox.com',
      badge: 'Intermediate to Advanced',
    },
    {
      name: 'Blue Team Labs Online (BTLO)',
      category: 'Defensive Security & Threat Hunting',
      description:
        'Dedicated defensive cybersecurity training platform focused on SIEM log analysis, memory forensics, digital forensics (DFIR), and malware analysis.',
      recommendedPaths: [
        'Investigating Phishing Emails',
        'Network Analysis with Wireshark & Zeek',
        'Windows Event Log Forensics',
      ],
      url: 'https://blueteamlabs.online',
      badge: 'Defensive / SOC Focus',
    },
  ];

  const careerTracks = [
    {
      title: 'Cloud Security Engineer',
      icon: Cloud,
      skills: 'AWS/GCP IAM Policies, CloudTrail/Cloud Audit, Terraform IaC Scanning, Kubernetes / Container Hardening, CSPM',
      focus: 'Growing career trajectory protecting modern multi-cloud workloads, serverless architectures, and zero-trust identity pipelines.',
    },
    {
      title: 'Security Operations Center (SOC) / Blue Team',
      icon: Shield,
      skills: 'SIEM (Splunk, Elastic, Sentinel), Network Forensics, Wireshark, Incident Response (IR) Playbooks, EDR Triaging',
      focus: 'Defending organizations in real time by monitoring alerts, triaging anomalous network traffic, and containing active intrusion attempts.',
    },
    {
      title: 'Application Security (AppSec)',
      icon: Terminal,
      skills: 'SAST/DAST tooling, Threat Modeling, Secure Code Review, CI/CD Pipeline Security, OWASP Top 10 remediation',
      focus: 'Collaborating directly with software engineering teams to embed security controls throughout the software development lifecycle.',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">Continue Learning: Pathways & Practice Platforms</h2>
            <Explainer
              term="Learning Roadmaps"
              title="Career Roadmaps & Community Practice"
              summary="Structured pathways that transition foundational networking knowledge into hands-on defensive engineering and security operations."
              whyItMatters="Certifications and portfolio projects carry the most weight when supported by verified profiles on established wargame platforms like TryHackMe or PortSwigger Academy."
            />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Curated resources for advancing toward cloud security, SOC operations, and AppSec engineering.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
          <Award className="w-4 h-4" />
          <span>Curated for Career Growth</span>
        </div>
      </div>

      {/* Platform Cards */}
      <div className="space-y-4">
        <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-400 font-mono px-1">
          Interactive Practice Platforms
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {platforms.map((platform) => (
            <div
              key={platform.name}
              className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3 flex flex-col justify-between hover:border-slate-700 transition-colors"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-mono text-cyan-400 font-semibold">{platform.category}</span>
                  <span className="text-[11px] px-2 py-0.5 bg-slate-800 text-slate-300 rounded font-mono">
                    {platform.badge}
                  </span>
                </div>

                <h4 className="text-base font-bold text-white">{platform.name}</h4>
                <p className="text-xs text-slate-300 leading-relaxed">{platform.description}</p>

                <div className="pt-2">
                  <span className="text-[11px] font-semibold text-slate-400 block mb-1">
                    Recommended Pathways:
                  </span>
                  <ul className="text-xs text-slate-300 space-y-1">
                    {platform.recommendedPaths.map((path, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-cyan-400 mt-0.5">•</span>
                        <span>{path}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex justify-end">
                <a
                  href={platform.url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  <span>Explore Platform</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Career Trajectories */}
      <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-2xl space-y-4">
        <div className="space-y-1">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Compass className="w-4 h-4 text-cyan-400" />
            <span>Target Security Career Specializations</span>
          </h3>
          <p className="text-xs text-slate-400">
            Skills to emphasize in projects and interviews as you grow from general networking into modern security roles.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          {careerTracks.map((track) => {
            const Icon = track.icon;
            return (
              <div
                key={track.title}
                className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl space-y-2"
              >
                <div className="flex items-center gap-2 font-bold text-slate-200">
                  <div className="w-7 h-7 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-cyan-400">
                    <Icon className="w-4 h-4" />
                  </div>
                  <span>{track.title}</span>
                </div>
                <p className="text-slate-300 text-xs leading-relaxed">{track.focus}</p>
                <div className="pt-1 text-[11px] font-mono text-cyan-400/90">
                  <span className="text-slate-400">Key competencies:</span> {track.skills}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
