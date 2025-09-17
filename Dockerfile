FROM rust:1.89

# Install Foundry/Anvil
RUN curl -L https://foundry.paradigm.xyz | bash
RUN /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"

WORKDIR /app

CMD ["cargo", "test", "--lib"]
