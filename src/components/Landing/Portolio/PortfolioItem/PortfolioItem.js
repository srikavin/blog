import React from 'react'
import styles from './PortfolioItem.module.css'

class PortfolioItem extends React.Component {
    constructor(props) {
        super(props);
    }

    redirect(url) {
        return () => {
            window.open(url, '_blank')
        }
    }

    render() {
        return (
            <div className={styles.portfolioItem}>
                <div className={styles.title}>{this.props.name}</div>
                <div className={styles.description}>{this.props.description}</div>
                <div className={styles.links}>
                    {this.props.custom ? <div className={styles.custom + ' ' + styles.portfolioExternalButton}
                                              onClick={this.redirect(this.props.custom)}>{this.props.customName}</div> :
                        <div>&nbsp;</div>}
                    {this.props.github ? <div className={styles.github + ' ' + styles.portfolioExternalButton}
                                              onClick={this.redirect(this.props.github)}>{this.props.githubName ? this.props.githubName : "Github"}</div> :
                        <div>&nbsp;</div>}
                </div>
            </div>
        );
    }
}

export default PortfolioItem;