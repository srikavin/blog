import React from 'react'
import styles from './Portfolio.module.css'
import PortfolioItem from "./PortfolioItem/PortfolioItem";

class Portfolio extends React.Component {
    render() {
        return (
            <div>
                <div className={styles.portfolioHeader}>Projects</div>
                <PortfolioItem name="BookKeeper"
                               description="A library management system that placed first at the 2018 Florida FBLA conference"
                               github="https://github.com/srikavin/BookKeeper"
                />
                <PortfolioItem name="Quizza"
                               description="A mobile quiz game with a built-in editor, online multiplayer, and offline studying"
                               github="https://github.com/srikavin/Quizza-Android"
                               githubName="Github (App)"
                               custom="https://github.com/srikavin/Quizza-GameServer"
                               customName="Github (Multiplayer Server)"
                />
                <PortfolioItem name="Conway's Game of Life"
                               description="An implementation of Conway's Game of Life in javascript"
                               github="https://github.com/srikavin/game-of-life"
                               custom="https://srikavin.github.io/game-of-life/index.html"
                               customName="Link"
                />
                <PortfolioItem name="Chest Randomizer" description="A Minecraft server plugin with 225,000+ installs"
                               github="https://github.com/srikavin/Chest-Randomizer"
                               custom="https://dev.bukkit.org/projects/chest-randomizer"
                               customName="Bukkit Dev"
                />
                    <PortfolioItem name="FactorySim"
                                   description="A game written using LWJGL and OpenGL in Java"
                                   github="https://github.com/srikavin/factorysim"
                    />
                    <PortfolioItem name="Chess" description="A chess game server written in Java using Glade"
                                   github="https://github.com/srikavin/Chess"
                                   githubName="Github (Backend)"
                                   custom="https://github.com/srikavin/Chess-Web"
                                   customName="Github (Frontend)"
                    />
                    <PortfolioItem name="Glade"
                                   description="A web server written in Java with an event-driven and modular design"
                                   github="https://github.com/srikavin/Glade"
                    />
                    <PortfolioItem name="epistle"
                                   description="Chat server and client with a drop-and-play plugin system and permission support"
                                   github="https://github.com/srikavin/epistle"
                    />
                    <PortfolioItem name="JPL"
                                   description="A basic interpreted language written in Java with a lexer, interpreter, and parser included in Glade"
                                   github="https://github.com/srikavin/JPL"
                    />
                    <PortfolioItem name="srikavin.me"
                                   description="A personal website created with React with a backend written using MongoDB and Express"
                                   github="https://github.com/srikavin/blog-api"
                                   githubName="Github (Backend)"
                                   custom="https://github.com/srikavin/blog"
                                   customName="Github (Frontend)"
                    />
            </div>
        );
    }
}

export default Portfolio;