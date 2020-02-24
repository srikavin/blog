import React from 'react'
import styles from './PortfolioItem.module.css'

class PortfolioItem extends React.Component {
    render() {
        return (
            <div className={styles.portfolioItem}>
                <div className={styles.title}>{this.props.name}</div>
                <div className={styles.description}>{this.props.description}</div>
                <div className={styles.links}>
                    {this.props.custom ?
                        <a href={this.props.custom} className={styles.custom + ' ' + styles.portfolioExternalButton}>
                            {this.props.customName}
                        </a> :
                        <div>&nbsp;</div>}
                    {this.props.github ?
                        <a href={this.props.github} className={styles.github + ' ' + styles.portfolioExternalButton}>
                            {this.props.githubName ? this.props.githubName : "Github"}
                        </a> :
                        <div>&nbsp;</div>}
                </div>
            </div>
        );
    }
}

export default PortfolioItem;