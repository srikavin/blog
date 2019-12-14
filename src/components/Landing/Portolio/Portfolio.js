import React from 'react'
import styles from './Portfolio.module.css'
import PortfolioItem from "./PortfolioItem/PortfolioItem";
import PropTypes from 'prop-types';


class Portfolio extends React.Component {
    render() {
        return (
            <div>
                <div className={styles.portfolioHeader}>Projects</div>
                {
                    this.props.items.map((e) => {
                        return (<PortfolioItem
                            key={e.name}
                            name={e.name}
                            description={e.description}
                            github={e.github}
                            githubName={e.githubName}
                            custom={e.custom}
                            customName={e.customName}
                        />)
                    })
                }
            </div>
        );
    }
}

Portfolio.propTypes = {
    items: PropTypes.array
};

export default Portfolio;