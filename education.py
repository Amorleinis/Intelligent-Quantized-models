import streamlit as st
import pandas as pd
import plotly.express as px

def app():
    """Educational page about quantum security concepts."""
    st.title("🎓 Quantum Security Education")
    st.markdown("Learn about quantum computing threats and security concepts")
    
    # Navigation tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "Quantum Computing Basics",
        "Quantum Security Threats",
        "Quantum-Resistant Solutions",
        "Quantum Security Glossary"
    ])
    
    # Tab 1: Quantum Computing Basics
    with tab1:
        st.header("Quantum Computing Fundamentals")
        
        st.markdown("""
        ### What is Quantum Computing?
        
        Quantum computing is a type of computing that uses quantum-mechanical phenomena, such as superposition and entanglement, to perform operations on data. Unlike classical computers that use bits (0 or 1), quantum computers use quantum bits or "qubits" that can exist in multiple states simultaneously.
        
        ### Key Quantum Concepts
        
        #### Superposition
        Unlike classical bits, which must be either 0 or 1, qubits can exist in a superposition of both states simultaneously. This allows quantum computers to process vast amounts of possibilities all at once.
        
        #### Entanglement
        When qubits become entangled, the state of one qubit instantly influences the state of another, regardless of the distance between them. Einstein called this "spooky action at a distance."
        
        #### Quantum Interference
        Quantum algorithms manipulate qubits to increase the probability of correct answers and decrease the probability of wrong answers through quantum interference.
        
        ### Quantum Computing Applications
        
        - **Cryptography**: Breaking certain encryption methods and creating new, more secure ones
        - **Drug Discovery**: Simulating molecular interactions for pharmaceutical research
        - **Optimization Problems**: Solving complex logistics and scheduling challenges
        - **Machine Learning**: Accelerating certain AI algorithms and calculations
        - **Financial Modeling**: Analyzing risk and optimizing portfolios more effectively
        
        ### Current State of Quantum Computing
        
        Today's quantum computers are in the early stages of development, with limited numbers of qubits and high error rates. They operate in controlled laboratory environments at extremely low temperatures. However, research and investment in the field are accelerating rapidly.
        
        Major technology companies like IBM, Google, Microsoft, and several specialized startups are racing to build increasingly powerful quantum computers.
        """)
        
        # Simple diagram of a qubit vs a classical bit
        st.markdown("### Classical Bit vs. Qubit")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            #### Classical Bit
            - Can be in state 0 OR 1
            - Deterministic behavior
            - Based on transistors and voltage levels
            """)
            
            # Simple ASCII art for classical bit
            st.code("""
            Classical Bit:
            
                ┌───┐
            ───►│ 0 │
                └───┘
                  OR
                ┌───┐
            ───►│ 1 │
                └───┘
            """)
        
        with col2:
            st.markdown("""
            #### Quantum Bit (Qubit)
            - Can be in superposition of 0 AND 1
            - Probabilistic behavior
            - Based on quantum mechanical properties
            """)
            
            # Simple ASCII art for qubit
            st.code("""
            Qubit:
            
                ┌─────────────┐
            ───►│ α|0⟩ + β|1⟩ │
                └─────────────┘
            
            where |α|² + |β|² = 1
            """)
    
    # Tab 2: Quantum Security Threats
    with tab2:
        st.header("Quantum Security Threats")
        
        st.markdown("""
        ### How Quantum Computing Threatens Current Cryptography
        
        Quantum computers pose a significant threat to many current cryptographic systems that secure our digital infrastructure. Here's why:
        
        #### Shor's Algorithm
        
        Developed by mathematician Peter Shor in 1994, Shor's algorithm can efficiently factor large numbers and compute discrete logarithms on a quantum computer. This directly threatens:
        
        - **RSA Encryption**: Based on the difficulty of factoring large prime numbers
        - **ECC (Elliptic Curve Cryptography)**: Based on the discrete logarithm problem
        - **Diffie-Hellman Key Exchange**: Used for secure key exchange between parties
        
        These algorithms protect most of today's secure communications, including:
        - HTTPS websites
        - VPN connections
        - Encrypted messaging apps
        - Digital signatures
        - Secure financial transactions
        
        #### Grover's Algorithm
        
        Grover's algorithm provides a quadratic speedup for searching unsorted databases, which affects:
        
        - **Symmetric Encryption** (e.g., AES): Reduces security by effectively halving the key length
        - **Hash Functions**: Makes it easier to find collisions or reverse hashes
        
        ### Timeline of Quantum Threat
        
        While large-scale quantum computers capable of breaking RSA encryption don't exist yet, the timeline for their development is uncertain:
        
        - **Today**: Small-scale quantum computers with 50-100+ noisy qubits exist
        - **5-10 years**: Error-corrected quantum computers with hundreds of qubits may emerge
        - **10-20 years**: Many experts believe quantum computers could break current cryptographic systems
        
        ### "Harvest Now, Decrypt Later" Attacks
        
        A current threat involves adversaries collecting encrypted data today with the intention of decrypting it once quantum computers become powerful enough. This is particularly concerning for data that needs to remain confidential for many years.
        """)
        
        # Visualization of cryptographic algorithms at risk
        st.subheader("Cryptographic Algorithms at Risk")
        
        # Create dataframe for visualization
        crypto_risk_data = pd.DataFrame({
            'Algorithm': ['RSA-2048', 'ECC-256', 'AES-128', 'AES-256', 'SHA-256', 'SHA-3'],
            'Risk Level': [95, 90, 50, 25, 50, 25],
            'Category': ['Asymmetric', 'Asymmetric', 'Symmetric', 'Symmetric', 'Hash Function', 'Hash Function']
        })
        
        # Create the bar chart
        fig = px.bar(
            crypto_risk_data, 
            x='Algorithm', 
            y='Risk Level', 
            color='Category',
            title='Vulnerability of Cryptographic Algorithms to Quantum Attacks',
            labels={'Risk Level': 'Vulnerability (%)'},
            color_discrete_map={'Asymmetric': '#FF6B6B', 'Symmetric': '#4ECDC4', 'Hash Function': '#FFD166'}
        )
        
        fig.update_layout(xaxis_title='Cryptographic Algorithm', yaxis_title='Vulnerability to Quantum Attacks (%)')
        st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("""
        **Note**: Asymmetric encryption algorithms like RSA and ECC are most vulnerable to quantum attacks through Shor's algorithm. Symmetric algorithms like AES-256 remain relatively secure but would need larger key sizes to maintain current security levels against Grover's algorithm.
        """)
    
    # Tab 3: Quantum-Resistant Solutions
    with tab3:
        st.header("Quantum-Resistant Security Solutions")
        
        st.markdown("""
        ### Post-Quantum Cryptography (PQC)
        
        Post-quantum cryptography refers to cryptographic algorithms that are believed to be secure against attacks from quantum computers. Unlike quantum key distribution, these are classical algorithms designed to resist quantum attacks.
        
        #### NIST PQC Standardization
        
        The National Institute of Standards and Technology (NIST) has been running a process to standardize quantum-resistant cryptographic algorithms. In July 2022, NIST selected the first set of algorithms for standardization:
        
        **Selected Algorithms:**
        
        1. **CRYSTALS-Kyber** (Key Establishment)
           - Lattice-based cryptography
           - Balance of key size and security
        
        2. **CRYSTALS-Dilithium** (Digital Signatures)
           - Lattice-based digital signature scheme
           - Efficient verification
        
        3. **FALCON** (Digital Signatures)
           - Lattice-based alternative with smaller signatures
           - Higher computational requirements
        
        4. **SPHINCS+** (Digital Signatures)
           - Hash-based signature scheme
           - Conservative security assumptions but larger signatures
        
        #### Categories of Post-Quantum Algorithms
        
        1. **Lattice-based Cryptography**
           - Based on mathematical problems involving lattices
           - Examples: CRYSTALS-Kyber, CRYSTALS-Dilithium, FALCON
        
        2. **Hash-based Cryptography**
           - Security relies on the properties of cryptographic hash functions
           - Examples: SPHINCS+, XMSS
        
        3. **Code-based Cryptography**
           - Based on error-correcting codes
           - Examples: Classic McEliece
        
        4. **Multivariate Cryptography**
           - Based on the difficulty of solving systems of multivariate equations
           - Examples: Rainbow (no longer considered secure)
        
        5. **Isogeny-based Cryptography**
           - Based on finding paths between isogenous elliptic curves
           - Examples: SIKE (recently broken)
        
        ### Quantum Key Distribution (QKD)
        
        Quantum Key Distribution uses quantum mechanics principles to establish secure communication between parties.
        
        #### Key Features
        
        - Uses quantum properties to detect eavesdropping
        - Provides information-theoretic security
        - Requires specialized hardware (not just software)
        - Limited by distance (typically <100km without quantum repeaters)
        
        #### Protocols
        
        - **BB84**: First QKD protocol by Bennett and Brassard
        - **E91**: Uses quantum entanglement
        - **BBM92**: Modified BB84 using entanglement
        
        ### Hybrid Approaches
        
        The most practical approach during the transition period is to use hybrid cryptographic solutions:
        
        - Combining current algorithms with post-quantum algorithms
        - Providing security even if one system is compromised
        - Example: Using both RSA and CRYSTALS-Kyber for key exchange
        """)
        
        # Visualization of PQC algorithm types and properties
        st.subheader("Post-Quantum Cryptography Comparison")
        
        # Create dataframe for visualization
        pqc_data = pd.DataFrame({
            'Algorithm Type': [
                'Lattice-based', 'Lattice-based', 'Hash-based', 'Hash-based', 
                'Code-based', 'Multivariate', 'Isogeny-based'
            ],
            'Key/Signature Size': [
                3, 2, 5, 4, 5, 3, 1
            ],
            'Computational Efficiency': [
                4, 4, 3, 3, 2, 4, 2
            ],
            'Confidence in Security': [
                4, 4, 5, 5, 4, 2, 2
            ],
            'Example Algorithm': [
                'CRYSTALS-Kyber', 'CRYSTALS-Dilithium', 'SPHINCS+', 'XMSS', 
                'Classic McEliece', 'Rainbow (broken)', 'SIKE (broken)'
            ]
        })
        
        # Calculate a combined score (higher is better)
        pqc_data['Overall Score'] = (
            pqc_data['Computational Efficiency'] + 
            pqc_data['Confidence in Security'] - 
            pqc_data['Key/Signature Size']/2
        )
        
        # Create the scatter plot
        fig = px.scatter(
            pqc_data,
            x='Key/Signature Size',
            y='Computational Efficiency',
            size='Confidence in Security',
            color='Algorithm Type',
            hover_name='Example Algorithm',
            size_max=15,
            title='Comparison of Post-Quantum Cryptography Approaches',
            labels={
                'Key/Signature Size': 'Key/Signature Size (larger = worse)',
                'Computational Efficiency': 'Computational Efficiency (higher = better)'
            }
        )
        
        # Update layout
        fig.update_layout(
            xaxis=dict(
                tickmode='array',
                tickvals=[1, 2, 3, 4, 5],
                ticktext=['Very Small', 'Small', 'Medium', 'Large', 'Very Large']
            ),
            yaxis=dict(
                tickmode='array',
                tickvals=[1, 2, 3, 4, 5],
                ticktext=['Very Slow', 'Slow', 'Medium', 'Fast', 'Very Fast']
            )
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("""
        **Note**: This chart compares different approaches to post-quantum cryptography. Ideal algorithms would appear in the upper-left quadrant (high efficiency, small key size). Size of the dots indicates confidence in security.
        """)
    
    # Tab 4: Quantum Security Glossary
    with tab4:
        st.header("Quantum Security Glossary")
        
        st.markdown("""
        ### Key Terms in Quantum Security
        
        Below is a glossary of important terms related to quantum computing and quantum-resistant security:
        """)
        
        # Create two columns for the glossary
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            #### Quantum Computing Terms
            
            **Qubit**
            : The basic unit of quantum information, analogous to a classical bit but capable of existing in superposition.
            
            **Superposition**
            : A quantum mechanical property that allows qubits to exist in multiple states simultaneously.
            
            **Entanglement**
            : A quantum phenomenon where pairs or groups of particles are generated or interact in ways such that the quantum state of each particle cannot be described independently.
            
            **Quantum Decoherence**
            : The loss of quantum coherence, or the breaking down of a superposition state due to interaction with the environment.
            
            **Quantum Gate**
            : The quantum computing equivalent of classical logic gates, operating on qubits.
            
            **Quantum Circuit**
            : A sequence of quantum gates operating on a collection of qubits.
            
            **Quantum Supremacy/Advantage**
            : The point at which a quantum computer can solve a problem that a classical computer cannot solve in feasible time.
            
            **Shor's Algorithm**
            : A quantum algorithm for integer factorization, which poses a threat to RSA and other public-key cryptography systems.
            
            **Grover's Algorithm**
            : A quantum search algorithm that provides a quadratic speedup for unstructured search problems.
            """)
        
        with col2:
            st.markdown("""
            #### Quantum Security Terms
            
            **Post-Quantum Cryptography (PQC)**
            : Classical cryptographic algorithms believed to be secure against attacks by quantum computers.
            
            **Quantum Key Distribution (QKD)**
            : A secure communication method that uses principles of quantum mechanics to establish a shared key.
            
            **Quantum-Resistant Algorithm**
            : An encryption algorithm designed to remain secure even against attacks by quantum computers.
            
            **Lattice-Based Cryptography**
            : A type of post-quantum cryptography based on problems in lattice theory, such as finding the shortest vector in a high-dimensional lattice.
            
            **Hash-Based Cryptography**
            : Cryptographic systems based on hash functions, often used for quantum-resistant digital signatures.
            
            **Hybrid Cryptography**
            : The use of multiple cryptographic algorithms together (e.g., traditional and post-quantum) to ensure security.
            
            **Quantum Random Number Generator (QRNG)**
            : A device that generates random numbers based on quantum physical processes, providing true randomness.
            
            **Harvest Now, Decrypt Later**
            : An attack strategy where encrypted data is collected now with the intention of decrypting it later when quantum computers become available.
            
            **Cryptographic Agility**
            : The ability to quickly switch between cryptographic algorithms without significant system changes.
            """)
        
        # Add a section on practical advice
        st.markdown("""
        ### Practical Advice for Organizations
        
        1. **Inventory Cryptographic Assets**: Identify where and how cryptography is used in your systems.
        
        2. **Assess Risks**: Determine which systems contain data that must remain secure for many years.
        
        3. **Develop a Transition Plan**: Create a roadmap for migrating to quantum-resistant algorithms.
        
        4. **Implement Crypto-Agility**: Design systems to easily switch cryptographic algorithms.
        
        5. **Monitor Developments**: Stay informed about advancements in both quantum computing and post-quantum cryptography.
        
        6. **Begin Testing PQC**: Start experimenting with NIST-recommended algorithms in non-production environments.
        
        7. **Consider Hybrid Approaches**: Implement both classical and post-quantum algorithms for critical systems.
        """)
    
    # Resources section
    st.header("Additional Resources")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### Learn More
        
        **Official Sources:**
        - [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
        - [Quantum Computing Report](https://quantumcomputingreport.com/)
        - [NSA Quantum Computing and Post-Quantum Cryptography FAQ](https://www.nsa.gov/portals/75/documents/what-we-do/cybersecurity/professional-resources/ctr-nsa-technology-forecast-quantum-computing.pdf)
        
        **Academic Papers:**
        - "Post-Quantum Cryptography: Current State and Quantum Mitigation" - ENISA, 2021
        - "Quantum-Safe Cryptography and Security" - ETSI, 2015
        """)
    
    with col2:
        st.markdown("""
        ### Tools and Standards
        
        **Open Source Libraries:**
        - [Open Quantum Safe](https://openquantumsafe.org/) - Open source project for prototyping quantum-resistant cryptography
        - [Liboqs](https://github.com/open-quantum-safe/liboqs) - C library for quantum-resistant cryptographic algorithms
        
        **Standards Development:**
        - [IETF Quantum-Safe Cryptography](https://datatracker.ietf.org/wg/qsh/about/)
        - [ETSI Quantum Safe Cryptography](https://www.etsi.org/technologies/quantum-safe-cryptography)
        """)
    
    # Disclaimer
    st.caption("Note: This educational content is provided for informational purposes only. The field of quantum computing and quantum-resistant cryptography is rapidly evolving, and this information may not reflect the most current developments.")

if __name__ == "__main__":
    app()
