import React from 'react';
import PropTypes from 'prop-types';
import type {CommentSchema} from "../../../data/resource/post";
import {PostStore} from "../../../data/resource/post";
import Comment from "./Comment/Comment";

import styles from './CommentsSection.module.css'
import config from '../../../config'


class CommentsSection extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            loading: true,
            comments: [],
            alert: undefined,
            alertTimeout: -1,
            name: '',
            email: '',
            comment: '',
            captcha_id: undefined
        };

        this.scrollRef = React.createRef();
        this.handleClearReplyTo = this.handleClearReplyTo.bind(this);
        this.handleReplyTo = this.handleReplyTo.bind(this);
    }

    componentDidMount(): void {
        PostStore.getCommentsForPost(this.props.postId).then(e => {
            this.setState({
                comments: e,
                loading: false
            });
        });
    }

    componentDidUpdate() {
        if (!this.state.loading && this.state.captcha_id === undefined) {
            this.setState({
                captcha_id: window.grecaptcha.render('comments_recaptcha', {sitekey: config["recaptcha-sitekey"]})
            });
        }
    }

    handleFormSubmit(e) {
        e.preventDefault();

        this.setAlert('');

        if (this.state.captcha_id === undefined) {
            this.setAlert('Failed to load ReCaptcha', 'error');
            return;
        }

        let response = window.grecaptcha.getResponse(this.state.captcha_id);
        if (response === '' || response === undefined) {
            this.setAlert('ReCaptcha Invalid', 'error');
            return;
        }

        let {name, email, comment, parent} = this.state;
        PostStore.createCommentOnPost(this.props.postId, response, name, email, comment, parent)
            .then(() => {
                PostStore.getCommentsForPost(this.props.postId).then(e => {
                    this.setState({
                        comments: e,
                        loading: false,
                        comment: ''
                    });


                    if (this.state.parentRef) {
                        window.scrollTo(0, this.state.parentRef.current.offsetTop);
                    }
                    this.setAlert('Comment Posted', 'success');

                    this.handleClearReplyTo();
                    window.grecaptcha.reset(this.state.captcha_id);
                });
            });
    }

    setAlert(message, type: 'error' | 'success') {
        window.clearTimeout(this.state.alertTimeout);

        this.setState({
            alert: message,
            alertType: type,
            alertTimeout: setTimeout(() => {
                this.setState({alert: undefined});
            }, 10000)
        });

    }

    renderAlert() {
        if (!this.state.alert) {
            return null;
        }

        return (
            <div className={styles.alert + ' ' + styles[this.state.alertType]}>{this.state.alert}</div>
        )
    }

    generateSkeleton() {
        return (
            <div className={'content'}>
                <h2>Comments</h2>
                <Comment loading={true}/>
                <Comment loading={true}/>
                <Comment loading={true}/>
                <Comment loading={true}/>
                <Comment loading={true}/>
            </div>
        )
    }

    render() {
        if (this.state.loading) {
            return this.generateSkeleton();
        }

        return (
            <>
                <div className={'content'}>
                    <h2>Comments</h2>
                </div>
                <div className={'content'} ref={this.scrollRef}>
                    {this.renderAlert()}
                    <form onSubmit={(e) => this.handleFormSubmit(e)}>
                        <span className={styles.section}>
                            <label className={styles.label} htmlFor='name'>Name</label>
                            <input name='name' type='text' value={this.state.name} required={true}
                                   onChange={(e) => this.setState({name: e.target.value})}/> <br/>
                        </span>
                        <span className={styles.section}>
                            <label className={styles.label} htmlFor='email'>Email <small>(Used to display Gravatar image)</small></label>
                            <input name='name' type='email' value={this.state.email} required={true}
                                   onChange={(e) => this.setState({email: e.target.value})}/> <br/>
                        </span>
                        {this.state.parent ? (
                            <span className={styles.section}>
                                <label className={styles.label} htmlFor='parent'>Replying to: </label>
                                <small>
                                    <a onClick={this.handleClearReplyTo}>(clear)</a>
                                </small>
                                <input name='parent' value={this.state.parentName} required={true}
                                       disabled={true}/> <br/>
                            </span>
                        ) : null
                        }
                        <span className={styles.section}>
                            <label className={styles.label} htmlFor='content'>Comment</label>
                            <textarea name='content' value={this.state.comment} required={true}
                                      onChange={(e) => this.setState({comment: e.target.value})}/> <br/>
                        </span>
                        <div id="comments_recaptcha" className="g-recaptcha"/>
                        <button type='submit' className={styles.button}>Post Comment</button>
                    </form>
                </div>
                {this.state.loading ? this.generateSkeleton() :
                    <div className={'content ' + (this.props.className !== undefined ? this.props.className : '')}>
                        {this.state.comments.map((e: CommentSchema) => {
                            return <Comment key={e.id} id={e.id} contents={e.contents} gravatarUrl={e.gravatarUrl}
                                            username={e.username} nested={e.children} level={1}
                                            replyTo={this.handleReplyTo}/>
                        })}
                    </div>
                }
            </>
        );
    }

    handleReplyTo(id, name, ref) {
        this.setState({parent: id, parentName: name, parentRef: ref});
        window.scrollTo(0, this.scrollRef.current.offsetTop)
    }

    handleClearReplyTo() {
        this.setState({parent: undefined, parentName: undefined, parentRef: undefined});
    }
}

CommentsSection.propTypes = {
    className: PropTypes.string,
    postId: PropTypes.any
};

export default CommentsSection;